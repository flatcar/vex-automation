// Package glsa reads Gentoo Linux Security Advisories (GLSAs) from a
// local directory of GLSA XML files. Only the fields needed to match an
// advisory against installed versions are read; the full format is
// described in https://www.gentoo.org/glep/glep-0058.html.
//
// Flatcar is built from Gentoo ebuilds, so Gentoo's advisories apply to
// its ebuild packages. The directory usually comes from the sync-glsa
// command (package glsasync), and the advisories go to glsa.Match.
package glsa

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// GLSA is one advisory.
type GLSA struct {
	ID       string // e.g. "202604-03"
	Title    string
	CVEs     []string // sorted, from the advisory's references
	Packages []AffectedPackage
}

// AffectedPackage is one <package> entry of an advisory: a package and
// the version ranges in which it is vulnerable or not.
type AffectedPackage struct {
	CategoryName string // e.g. "sys-fs/fuse"
	Arch         string // e.g. "*", "amd64" or "amd64 x86"
	Unaffected   []VersionRange
	Vulnerable   []VersionRange
}

// VersionRange is one version condition, such as "ge 1.2.3" (>= 1.2.3).
type VersionRange struct {
	// Op is "ge", "gt", "le", "lt" or "eq" (Version may then end in "*"),
	// or "rge", "rgt", "rle", "rlt", which only compare the -rN revision
	// of the same version (see portage.Satisfies).
	Op string
	// Slot, if set, limits the range to one Portage SLOT.
	Slot    string
	Version string
}

// MatchesArch reports whether this entry applies to arch, e.g. "amd64".
// An empty arch or "*" means all architectures.
func (p AffectedPackage) MatchesArch(arch string) bool {
	if p.Arch == "" || p.Arch == "*" {
		return true
	}
	for _, entry := range strings.Fields(p.Arch) {
		if strings.TrimPrefix(entry, "~") == arch {
			return true
		}
	}
	return false
}

// ParseError lists the GLSA files that could not be parsed.
type ParseError struct {
	Errs []error // one per file
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%d GLSA file(s) failed to parse: %v", len(e.Errs), errors.Join(e.Errs...))
}

func (e *ParseError) Unwrap() []error { return e.Errs }

// LoadDir parses every glsa-*.xml file under dir, sorted by ID.
//
// A file that fails to parse doesn't stop the others: LoadDir returns
// every advisory that parsed together with a *ParseError, so the caller
// decides whether a partial set of advisories is acceptable.
func LoadDir(dir string) ([]GLSA, error) {
	paths, err := FindFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("walking GLSA directory %q: %w", dir, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no glsa-*.xml files found under %q", dir)
	}

	var glsas []GLSA
	var parseErrs []error
	for _, path := range paths {
		advisory, err := loadFile(path)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("parsing %q: %w", path, err))
			continue
		}
		glsas = append(glsas, advisory)
	}
	slices.SortStableFunc(glsas, func(a, b GLSA) int { return strings.Compare(a.ID, b.ID) })

	if len(parseErrs) > 0 {
		return glsas, &ParseError{Errs: parseErrs}
	}
	return glsas, nil
}

// FindFiles returns the paths of all glsa-*.xml files under dir, skipping
// ".git" directories.
func FindFiles(dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case entry.IsDir() && entry.Name() == ".git":
			return filepath.SkipDir
		case !entry.IsDir() && strings.HasPrefix(entry.Name(), "glsa-") && strings.HasSuffix(entry.Name(), ".xml"):
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}

// The parts of the GLSA XML format that we need.
type xmlGLSA struct {
	XMLName  xml.Name
	ID       string `xml:"id,attr"`
	Title    string `xml:"title"`
	Affected *struct {
		Packages []xmlPackage `xml:"package"`
	} `xml:"affected"`
	References []struct {
		Link string `xml:"link,attr"`
		Text string `xml:",chardata"`
	} `xml:"references>uri"`
}

type xmlPackage struct {
	Name       string     `xml:"name,attr"`
	Arch       string     `xml:"arch,attr"`
	Unaffected []xmlRange `xml:"unaffected"`
	Vulnerable []xmlRange `xml:"vulnerable"`
}

type xmlRange struct {
	Op      string `xml:"range,attr"`
	Slot    string `xml:"slot,attr"`
	Version string `xml:",chardata"`
}

var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

func loadFile(path string) (GLSA, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is under the user-provided directory.
	if err != nil {
		return GLSA{}, err
	}
	var parsed xmlGLSA
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return GLSA{}, err
	}
	if err := checkComplete(parsed); err != nil {
		return GLSA{}, err
	}

	advisory := GLSA{ID: parsed.ID, Title: strings.TrimSpace(parsed.Title)}
	for _, pkg := range parsed.Affected.Packages {
		advisory.Packages = append(advisory.Packages, AffectedPackage{
			CategoryName: pkg.Name,
			Arch:         pkg.Arch,
			Unaffected:   convertRanges(pkg.Unaffected),
			Vulnerable:   convertRanges(pkg.Vulnerable),
		})
	}
	for _, reference := range parsed.References {
		advisory.CVEs = append(advisory.CVEs, cvePattern.FindAllString(reference.Link+" "+reference.Text, -1)...)
	}
	slices.Sort(advisory.CVEs)
	advisory.CVEs = slices.Compact(advisory.CVEs)
	return advisory, nil
}

// checkComplete rejects an advisory that would otherwise silently match
// nothing: one without <affected>, or with a package that has no name or
// no ranges. An empty <affected> is fine: some GLSAs are notices that
// affect no package.
func checkComplete(parsed xmlGLSA) error {
	if parsed.XMLName.Local != "glsa" || parsed.ID == "" {
		return fmt.Errorf("not a GLSA document (root element <%s>, id %q)", parsed.XMLName.Local, parsed.ID)
	}
	if parsed.Affected == nil {
		return fmt.Errorf("GLSA %s has no <affected> element", parsed.ID)
	}
	for i, pkg := range parsed.Affected.Packages {
		if strings.TrimSpace(pkg.Name) == "" {
			return fmt.Errorf("GLSA %s: affected package #%d has no name", parsed.ID, i+1)
		}
		if len(pkg.Vulnerable) == 0 && len(pkg.Unaffected) == 0 {
			return fmt.Errorf("GLSA %s: affected package %q has no version ranges", parsed.ID, pkg.Name)
		}
	}
	return nil
}

func convertRanges(ranges []xmlRange) []VersionRange {
	converted := make([]VersionRange, len(ranges))
	for i, r := range ranges {
		converted[i] = VersionRange{Op: r.Op, Slot: r.Slot, Version: strings.TrimSpace(r.Version)}
	}
	return converted
}
