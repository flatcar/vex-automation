// Package sbom reads the SPDX SBOMs that Flatcar publishes for each image
// and sorts their packages by the vulnerability source that can check them:
// ebuild packages are checked against Gentoo's GLSAs, golang and cargo
// packages against OSV.dev.
//
// The package type comes from the package's purl, e.g.
// "pkg:ebuild/sys-apps/systemd@255.4-r2" or "pkg:golang/<module>@<version>".
//
// This is the first step of both generate and diff: the SBOM is the only
// record of what a release ships, and Document's three lists decide what
// gets checked (Packages by match.RunGLSA, OSVPackages by match.RunOSV) and
// what gets reported as unchecked (Skipped).
package sbom

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
)

// Package is one package from an SBOM.
type Package struct {
	// Category is the Portage category (e.g. "sys-apps") of an ebuild
	// package, or the purl type ("golang" or "cargo") of an OSV package.
	Category string
	// Name is the ebuild name (e.g. "systemd") or the Go module / crate
	// path (e.g. "github.com/golang-jwt/jwt/v4").
	Name string
	// Version is the installed version, e.g. "255.4-r2" or "v1.57.0".
	// Go "stdlib"/"toolchain" versions are normalized, see osvVersion.
	Version string
	// PURL is the purl exactly as written in the SBOM.
	PURL string
}

// CategoryName returns "category/name", the form GLSAs name packages in.
func (p Package) CategoryName() string {
	return p.Category + "/" + p.Name
}

// Document is what Load returns.
type Document struct {
	// Name is the SPDX document name. Flatcar's embeds the channel and
	// version, e.g. ".../amd64-usr/stable-4593.2.4-a1/rootfs".
	Name string
	// Packages are the ebuild packages, checked against GLSAs.
	Packages []Package
	// OSVPackages are the golang/cargo packages, checked against OSV.dev.
	OSVPackages []Package
	// Skipped are the packages no source can check (e.g. the kernel, with
	// its "pkg:generic" purl), so the gap can be reported.
	Skipped []SkippedPackage
}

// SkippedPackage is an SBOM package that no vulnerability source can check.
type SkippedPackage struct {
	Name    string
	Version string
	PURL    string // empty if the package has no purl
	Reason  string
	// Ecosystem and Module are set (like Package.Category and Name) only
	// for golang/cargo modules skipped because of their version, e.g.
	// "(devel)", so callers can recognize another copy of a checked module.
	Ecosystem string
	Module    string
}

// The parts of the SPDX JSON format that we need.
type spdxDocument struct {
	SPDXVersion string        `json:"spdxVersion"`
	Name        string        `json:"name"`
	Packages    []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name         string `json:"name"`
	VersionInfo  string `json:"versionInfo"`
	ExternalRefs []struct {
		ReferenceType    string `json:"referenceType"`
		ReferenceLocator string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

// Load reads the SPDX JSON SBOM at path. It fails if the SBOM has no
// package any source can check, since an empty VEX document would look
// like a clean bill of health.
func Load(path string) (Document, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is a CLI flag.
	if err != nil {
		return Document{}, fmt.Errorf("reading SBOM file %q: %w", path, err)
	}
	var spdx spdxDocument
	if err := json.Unmarshal(raw, &spdx); err != nil {
		return Document{}, fmt.Errorf("parsing SBOM file %q as SPDX JSON: %w", path, err)
	}
	if !strings.HasPrefix(spdx.SPDXVersion, "SPDX-") {
		return Document{}, fmt.Errorf("SBOM file %q is not an SPDX document (spdxVersion is %q)", path, spdx.SPDXVersion)
	}

	doc := Document{Name: spdx.Name}
	for _, pkg := range spdx.Packages {
		doc.add(pkg)
	}
	if len(doc.Packages) == 0 && len(doc.OSVPackages) == 0 {
		return Document{}, fmt.Errorf("SBOM file %q contains no ebuild, golang or cargo package to match", path)
	}
	return doc, nil
}

func (d *Document) add(pkg spdxPackage) {
	purl := choosePurl(pkg)
	switch ecosystem := purlType(purl); {
	case purl == "":
		d.skip(pkg, "", "no purl")
	case ecosystem == "ebuild":
		d.addEbuild(pkg, purl)
	case ecosystem == "golang" || ecosystem == "cargo":
		d.addOSV(pkg, purl, ecosystem)
	default:
		d.skip(pkg, purl, "unsupported purl type")
	}
}

// The version is always taken from versionInfo, not from the purl, where
// it may be percent-encoded.
func (d *Document) addEbuild(pkg spdxPackage, purl string) {
	category, name, ok := parseEbuildPurl(purl)
	if !ok {
		d.skip(pkg, purl, "malformed ebuild purl")
		return
	}
	d.Packages = append(d.Packages, Package{Category: category, Name: name, Version: pkg.VersionInfo, PURL: purl})
}

func (d *Document) addOSV(pkg spdxPackage, purl, ecosystem string) {
	module, ok := parseModulePurl(purl, ecosystem)
	switch {
	case !ok:
		d.skip(pkg, purl, "purl does not name a module that OSV.dev can be queried about")
	case !isQueryableVersion(pkg.VersionInfo):
		d.Skipped = append(d.Skipped, SkippedPackage{Name: pkg.Name, Version: pkg.VersionInfo, PURL: purl,
			Reason: "version is not queryable", Ecosystem: ecosystem, Module: module})
	default:
		d.OSVPackages = append(d.OSVPackages, Package{
			Category: ecosystem, Name: module, Version: osvVersion(ecosystem, module, pkg.VersionInfo), PURL: purl,
		})
	}
}

func (d *Document) skip(pkg spdxPackage, purl, reason string) {
	d.Skipped = append(d.Skipped, SkippedPackage{Name: pkg.Name, Version: pkg.VersionInfo, PURL: purl, Reason: reason})
}

// choosePurl picks the purl that decides how a package is checked: its
// first ebuild purl, else its first golang/cargo purl, else its first purl.
func choosePurl(pkg spdxPackage) string {
	var purls []string
	for _, ref := range pkg.ExternalRefs {
		if ref.ReferenceType == "purl" {
			purls = append(purls, ref.ReferenceLocator)
		}
	}
	if len(purls) == 0 {
		return ""
	}
	return slices.MinFunc(purls, func(a, b string) int { return purlPreference(a) - purlPreference(b) })
}

func purlPreference(purl string) int {
	switch purlType(purl) {
	case "ebuild":
		return 0
	case "golang", "cargo":
		return 1
	default:
		return 2
	}
}

// purlType returns the type of a purl: "ebuild" for "pkg:ebuild/...".
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	typ, _, hasSlash := strings.Cut(rest, "/")
	if !ok || !hasSlash {
		return ""
	}
	return typ
}

// parseEbuildPurl reads category and name from
// "pkg:ebuild/<category>/<name>@<version>".
func parseEbuildPurl(purl string) (category, name string, ok bool) {
	rest := strings.TrimPrefix(purl, "pkg:ebuild/")
	rest, _, _ = strings.Cut(rest, "@")
	rest, _, _ = strings.Cut(rest, "?")
	category, name, found := strings.Cut(rest, "/")
	if !found || category == "" || name == "" {
		return "", "", false
	}
	return category, name, true
}

// parseModulePurl reads the module or crate path from
// "pkg:<type>/<name>@<version>[?qualifiers][#subpath]".
//
// For golang, Syft puts the part of a module path below the repository in
// the subpath: "pkg:golang/github.com/golang-jwt/jwt@v4.5.1#v4" is module
// "github.com/golang-jwt/jwt/v4". Without it, OSV.dev would be asked about
// the parent module.
//
// Relative names such as "pkg:golang/../api@(devel)" are packages built
// from inside their own module, not real modules, and are rejected.
func parseModulePurl(purl, ecosystem string) (string, bool) {
	rest := strings.TrimPrefix(purl, "pkg:"+ecosystem+"/")
	rest, subpath, _ := strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	name, _, found := strings.Cut(rest, "@")
	if !found {
		return "", false
	}
	name, err := url.PathUnescape(name)
	if err != nil || name == "" || strings.HasPrefix(name, ".") {
		return "", false
	}
	if ecosystem != "golang" {
		return name, true
	}
	subpath, err = url.PathUnescape(strings.Trim(subpath, "/"))
	if err != nil {
		return "", false
	}
	if subpath != "" {
		name += "/" + subpath
	}
	return name, true
}

// isQueryableVersion rejects empty versions and Go placeholders like "(devel)".
func isQueryableVersion(version string) bool {
	version = strings.TrimSpace(version)
	return version != "" && !strings.HasPrefix(version, "(")
}

// osvVersion converts a Go stdlib/toolchain version to the form OSV.dev
// uses. Syft writes "go1.25.3", OSV.dev "1.25.3". Syft also keeps a
// GOEXPERIMENT suffix ("go1.26.10-X:nodwarf5"), which OSV.dev would read
// as a pre-release of 1.26.10, still vulnerable to what 1.26.10 fixed.
func osvVersion(ecosystem, module, version string) string {
	if ecosystem != "golang" || (module != "stdlib" && module != "toolchain") {
		return version
	}
	version = strings.TrimPrefix(version, "go")
	if i := strings.Index(version, "X:"); i > 0 && (version[i-1] == '-' || version[i-1] == ' ') {
		version = version[:i-1]
	}
	return version
}
