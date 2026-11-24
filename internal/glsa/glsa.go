// Package glsa reads a local mirror of the Gentoo GLSA (Gentoo Linux Security
// Advisory) XML corpus, as synced into flatcar/scripts' metadata/glsa/
// directory (see docs/current-state.md §3).
//
// Only the fields needed to match a GLSA against an installed package
// version are parsed; see https://www.gentoo.org/glep/glep-0058.html for the
// full schema.
package glsa

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// GLSA is a single parsed Gentoo Linux Security Advisory.
type GLSA struct {
	// ID is the advisory identifier, e.g. "202604-03".
	ID string
	// Title is the advisory's short title.
	Title string
	// CVEs are the CVE identifiers referenced by this advisory, extracted
	// from its <references> section.
	CVEs []string
	// Packages lists every <affected><package> entry in the advisory.
	Packages []AffectedPackage
}

// AffectedPackage is one <package> entry within a GLSA's <affected> section.
type AffectedPackage struct {
	// CategoryName is the Portage "category/name" this entry applies to,
	// e.g. "sys-fs/fuse".
	CategoryName string
	// Arch is the raw arch attribute (e.g. "*", "amd64", "amd64 x86"). "*"
	// means all architectures.
	Arch string
	// Unaffected lists the version ranges that are NOT vulnerable.
	Unaffected []VersionRange
	// Vulnerable lists the version ranges that ARE vulnerable.
	Vulnerable []VersionRange
}

// MatchesArch reports whether this package entry applies to arch (e.g.
// "amd64"). A GLSA arch of "*" or an empty attribute matches everything.
func (p AffectedPackage) MatchesArch(arch string) bool {
	if p.Arch == "" || p.Arch == "*" {
		return true
	}
	for _, a := range strings.Fields(p.Arch) {
		if strings.TrimPrefix(a, "~") == arch {
			return true
		}
	}
	return false
}

// VersionRange is a single <unaffected>/<vulnerable> version constraint.
type VersionRange struct {
	// Op is the comparison operator: one of "ge", "gt", "le", "lt", "eq"
	// (Version may end in "*" for a Portage glob match), or the
	// revision-only "rge", "rgt", "rle", "rlt", which compare only the -rN
	// revision of the same base version (see portage.Satisfies).
	Op string
	// Slot restricts the range to a specific Portage SLOT, if set.
	Slot string
	// Version is the version being compared against.
	Version string
}

// --- XML schema (subset) ---

type xmlGLSA struct {
	XMLName    xml.Name
	ID         string       `xml:"id,attr"`
	Title      string       `xml:"title"`
	Affected   xmlAffected  `xml:"affected"`
	References xmlReference `xml:"references"`
}

type xmlAffected struct {
	Packages []xmlPackage `xml:"package"`
}

type xmlPackage struct {
	Name       string     `xml:"name,attr"`
	Arch       string     `xml:"arch,attr"`
	Unaffected []xmlRange `xml:"unaffected"`
	Vulnerable []xmlRange `xml:"vulnerable"`
}

type xmlRange struct {
	Range   string `xml:"range,attr"`
	Slot    string `xml:"slot,attr"`
	Version string `xml:",chardata"`
}

type xmlReference struct {
	URIs []xmlURI `xml:"uri"`
}

type xmlURI struct {
	Link string `xml:"link,attr"`
	Text string `xml:",chardata"`
}

// cveRegexp matches CVE identifiers within GLSA reference text/links.
var cveRegexp = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// ParseError is returned by LoadDir when some GLSA files could not be
// parsed. The GLSAs that did parse are still returned alongside it, so a
// caller may choose to continue with a partial corpus.
type ParseError struct {
	// Errs holds one error per file that failed to parse.
	Errs []error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%d GLSA file(s) failed to parse: %v", len(e.Errs), errors.Join(e.Errs...))
}

func (e *ParseError) Unwrap() []error { return e.Errs }

// LoadDir walks dir (non-recursively is not enough for flatcar/scripts'
// layout, so this recurses) and parses every "glsa-*.xml" file it finds.
//
// Files that fail to parse don't stop the walk: every GLSA that parsed is
// returned together with a *ParseError listing each failure, so a single
// malformed advisory can never silently drop out of the corpus. Callers
// that want to proceed anyway can check for *ParseError with errors.As.
func LoadDir(dir string) ([]GLSA, error) {
	var (
		glsas     []GLSA
		parseErrs []error
		sawFiles  bool
	)

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// A sync-glsa-produced mirror contains a ".git" directory full of
			// non-GLSA internals; skip it entirely rather than walking it.
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasPrefix(d.Name(), "glsa-") || !strings.HasSuffix(d.Name(), ".xml") {
			return nil
		}
		sawFiles = true

		g, parseErr := loadFile(path)
		if parseErr != nil {
			parseErrs = append(parseErrs, fmt.Errorf("parsing %q: %w", path, parseErr))
			return nil
		}
		glsas = append(glsas, g)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking GLSA directory %q: %w", dir, err)
	}
	if !sawFiles {
		return nil, fmt.Errorf("no glsa-*.xml files found under %q", dir)
	}

	sort.Slice(glsas, func(i, j int) bool { return glsas[i].ID < glsas[j].ID })

	if len(parseErrs) > 0 {
		return glsas, &ParseError{Errs: parseErrs}
	}
	return glsas, nil
}

func loadFile(path string) (GLSA, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path comes from filepath.WalkDir over a user-provided directory.
	if err != nil {
		return GLSA{}, err
	}

	var x xmlGLSA
	if err := xml.Unmarshal(raw, &x); err != nil {
		return GLSA{}, err
	}
	if x.XMLName.Local != "glsa" || x.ID == "" {
		return GLSA{}, fmt.Errorf("not a GLSA document (root element <%s>, id %q)", x.XMLName.Local, x.ID)
	}

	g := GLSA{
		ID:    x.ID,
		Title: strings.TrimSpace(x.Title),
	}

	for _, p := range x.Affected.Packages {
		g.Packages = append(g.Packages, AffectedPackage{
			CategoryName: p.Name,
			Arch:         p.Arch,
			Unaffected:   convertRanges(p.Unaffected),
			Vulnerable:   convertRanges(p.Vulnerable),
		})
	}

	cveSet := map[string]bool{}
	for _, uri := range x.References.URIs {
		for _, m := range cveRegexp.FindAllString(uri.Link+" "+uri.Text, -1) {
			cveSet[m] = true
		}
	}
	for cve := range cveSet {
		g.CVEs = append(g.CVEs, cve)
	}
	sort.Strings(g.CVEs)

	return g, nil
}

func convertRanges(ranges []xmlRange) []VersionRange {
	out := make([]VersionRange, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, VersionRange{
			Op:      r.Range,
			Slot:    r.Slot,
			Version: strings.TrimSpace(r.Version),
		})
	}
	return out
}
