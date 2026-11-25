// Package diff compares the vulnerability findings of two SBOMs (an older
// and a newer Flatcar release) matched against the same vulnerability data,
// and classifies each (vulnerability, package) pair as fixed, removed,
// introduced, still affected or needing review. It is pure logic: loading
// SBOMs and running the matchers is up to the caller.
package diff

import (
	"sort"

	"github.com/flatcar/vex-automation/internal/match"
	"github.com/flatcar/vex-automation/internal/sbom"
)

// SchemaVersion is the version of the JSON document produced from Result.
const SchemaVersion = 1

// State is the condition of one (vulnerability, package) key on one side
// of the diff.
type State string

const (
	// StateAbsent means the package is not in that SBOM at all.
	StateAbsent State = "absent"
	// StateClean means the package is in that SBOM but no finding refers
	// to this vulnerability. For OSV.dev this is how a fix shows up, since
	// OSV.dev returns nothing for an unaffected version.
	StateClean State = "clean"
	// StateAffected means the most severe status among that side's findings for
	// the key is affected (match.StatusAffected).
	StateAffected State = State(match.StatusAffected)
	// StateUnderInvestigation mirrors match.StatusUnderInvestigation.
	StateUnderInvestigation State = State(match.StatusUnderInvestigation)
	// StateFixed mirrors match.StatusFixed.
	StateFixed State = State(match.StatusFixed)
	// StateNotAffected mirrors match.StatusNotAffected.
	StateNotAffected State = State(match.StatusNotAffected)
	// StateUnchecked means no finding shows the package affected, but that
	// side also ships a copy whose version could not be checked (see
	// sbom.SkippedPackage.Module), so it may still be affected.
	StateUnchecked State = "unchecked"
)

// Bucket classifies how a key changed between the two releases.
type Bucket string

const (
	// BucketFixed means the key was affected and the package is still
	// shipped, but no longer affected.
	BucketFixed Bucket = "fixed"
	// BucketRemoved means the key was affected and the package is gone.
	BucketRemoved Bucket = "removed"
	// BucketIntroduced means the key is affected now but was not before.
	BucketIntroduced Bucket = "introduced"
	// BucketStillAffected means the key is affected on both sides.
	BucketStillAffected Bucket = "still_affected"
	// BucketReview means at least one side could not be evaluated
	// (under_investigation or unchecked), so neither a fix, a removal nor an
	// introduction is established.
	BucketReview Bucket = "review"
)

// bucketOrder is the order in which entries are listed.
var bucketOrder = map[Bucket]int{
	BucketFixed:         0,
	BucketRemoved:       1,
	BucketIntroduced:    2,
	BucketStillAffected: 3,
	BucketReview:        4,
}

// Side is one release: its SBOM and the findings matched against it.
type Side struct {
	Doc      sbom.Document
	Findings []match.Finding
}

// Input is the data Compute compares. Both sides must have been matched
// against the same vulnerability data, or the result is meaningless.
type Input struct {
	Old Side
	New Side
}

// Result is the outcome of a diff, encoded as the "flatcar-vex diff" JSON
// document. Compute fills Summary, Entries and NotChecked; the caller fills
// the descriptive fields.
type Result struct {
	SchemaVersion int        `json:"schema_version"`
	Tooling       string     `json:"tooling"`
	Old           Release    `json:"old"`
	New           Release    `json:"new"`
	Summary       Summary    `json:"summary"`
	Entries       []Entry    `json:"entries"`
	NotChecked    NotChecked `json:"not_checked"`
}

// Release identifies one side of the diff.
type Release struct {
	SBOMName  string `json:"sbom_name"`
	ProductID string `json:"product_id"`
}

// Summary counts entries per bucket.
type Summary struct {
	Fixed         int `json:"fixed"`
	Removed       int `json:"removed"`
	Introduced    int `json:"introduced"`
	StillAffected int `json:"still_affected"`
	Review        int `json:"review"`
}

// Entry is one reported (vulnerability, package) key.
type Entry struct {
	// ID is a CVE ID, or the source's own ID when there is no CVE.
	ID     string `json:"id"`
	Bucket Bucket `json:"bucket"`
	// Package is "category/name" for ebuilds and the module path for
	// golang/cargo packages.
	Package string `json:"package"`
	// Ecosystem is "ebuild", "golang" or "cargo".
	Ecosystem  string   `json:"ecosystem"`
	Old        SideInfo `json:"old"`
	New        SideInfo `json:"new"`
	Sources    []string `json:"sources"`
	Advisories []string `json:"advisories"`
	Notes      []string `json:"notes"`
}

// SideInfo describes a key on one side of the diff.
type SideInfo struct {
	State State `json:"state"`
	// Versions are all versions of the package in that SBOM.
	Versions []string `json:"versions"`
}

// NotChecked lists what the diff could not look at, so an empty result is
// never mistaken for "nothing changed".
type NotChecked struct {
	Old         []Skipped `json:"old"`
	New         []Skipped `json:"new"`
	OSVDisabled bool      `json:"osv_disabled"`
}

// Skipped is an SBOM package that no vulnerability source covers.
type Skipped struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	Reason  string `json:"reason"`
	// Ecosystem and Module identify a golang/cargo module skipped only
	// because its version can't be queried (see sbom.SkippedPackage).
	Ecosystem string `json:"ecosystem,omitempty"`
	Module    string `json:"module,omitempty"`
}

type key struct {
	id      string
	catName string
}

// presence records, per package CategoryName, which versions a side ships
// and whether some copy of it could not be checked.
type presence struct {
	ecosystem string
	pkg       string
	versions  map[string]bool
	unchecked bool
}

// Compute compares in.Old with in.New. The result is deterministic: it
// doesn't depend on the order of packages or findings.
func Compute(in Input) Result {
	oldPresent, newPresent := presenceOf(in.Old.Doc), presenceOf(in.New.Doc)
	oldByKey, newByKey := groupFindings(in.Old.Findings), groupFindings(in.New.Findings)

	keys := map[key]bool{}
	for k := range oldByKey {
		keys[k] = true
	}
	for k := range newByKey {
		keys[k] = true
	}

	entries := []Entry{}
	var summary Summary
	for k := range keys {
		oldState := stateOf(oldPresent, oldByKey, k)
		newState := stateOf(newPresent, newByKey, k)
		bucket, ok := classify(oldState, newState)
		if !ok {
			continue
		}

		// classify only reports keys present on at least one side.
		p := oldPresent[k.catName]
		if p == nil {
			p = newPresent[k.catName]
		}

		all := append(append([]match.Finding{}, oldByKey[k]...), newByKey[k]...)
		entries = append(entries, Entry{
			ID:         k.id,
			Bucket:     bucket,
			Package:    p.pkg,
			Ecosystem:  p.ecosystem,
			Old:        SideInfo{State: oldState, Versions: versionsOf(oldPresent[k.catName])},
			New:        SideInfo{State: newState, Versions: versionsOf(newPresent[k.catName])},
			Sources:    collect(all, func(f match.Finding) string { return f.Source }),
			Advisories: collect(all, func(f match.Finding) string { return f.RefID }),
			Notes:      collect(all, func(f match.Finding) string { return f.Note }),
		})
		summary.add(bucket)
	}

	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Bucket != b.Bucket {
			return bucketOrder[a.Bucket] < bucketOrder[b.Bucket]
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		return a.ID < b.ID
	})

	return Result{
		SchemaVersion: SchemaVersion,
		Summary:       summary,
		Entries:       entries,
		NotChecked: NotChecked{
			Old: skippedOf(in.Old.Doc.Skipped),
			New: skippedOf(in.New.Doc.Skipped),
		},
	}
}

// classify applies the bucket rules in order. ok is false for keys that
// are not worth reporting (e.g. fixed on both sides).
func classify(oldState, newState State) (Bucket, bool) {
	switch {
	case oldState == StateAffected && (newState == StateFixed || newState == StateNotAffected || newState == StateClean):
		return BucketFixed, true
	case oldState == StateAffected && newState == StateAbsent:
		return BucketRemoved, true
	case oldState == StateAffected && newState == StateAffected:
		return BucketStillAffected, true
	case unknown(oldState) || unknown(newState):
		// Checked before "introduced": an old state that couldn't be
		// evaluated doesn't show the vulnerability is new.
		return BucketReview, true
	case newState == StateAffected:
		return BucketIntroduced, true
	}
	return "", false
}

func unknown(s State) bool {
	return s == StateUnderInvestigation || s == StateUnchecked
}

func (s *Summary) add(b Bucket) {
	switch b {
	case BucketFixed:
		s.Fixed++
	case BucketRemoved:
		s.Removed++
	case BucketIntroduced:
		s.Introduced++
	case BucketStillAffected:
		s.StillAffected++
	case BucketReview:
		s.Review++
	}
}

func presenceOf(doc sbom.Document) map[string]*presence {
	m := map[string]*presence{}
	get := func(p sbom.Package) *presence {
		pr := m[p.CategoryName()]
		if pr == nil {
			pr = &presence{ecosystem: ecosystemOf(p), pkg: displayPackage(p), versions: map[string]bool{}}
			m[p.CategoryName()] = pr
		}
		pr.versions[p.Version] = true
		return pr
	}
	for _, p := range append(append([]sbom.Package{}, doc.Packages...), doc.OSVPackages...) {
		get(p)
	}
	for _, sk := range doc.Skipped {
		if sk.Module != "" {
			get(sbom.Package{Category: sk.Ecosystem, Name: sk.Module, Version: sk.Version}).unchecked = true
		}
	}
	return m
}

// ecosystemOf returns "ebuild" for Portage packages and the purl type for
// golang/cargo packages (which sbom.Load stores in Category).
func ecosystemOf(p sbom.Package) string {
	if p.Category == "golang" || p.Category == "cargo" {
		return p.Category
	}
	return "ebuild"
}

func displayPackage(p sbom.Package) string {
	if ecosystemOf(p) == "ebuild" {
		return p.CategoryName()
	}
	return p.Name
}

func groupFindings(findings []match.Finding) map[key][]match.Finding {
	m := map[key][]match.Finding{}
	for _, f := range findings {
		k := key{id: f.CVE, catName: f.Package.CategoryName()}
		m[k] = append(m[k], f)
	}
	return m
}

// stateOf returns the most severe state of k on one side. A copy that
// couldn't be checked makes the side unchecked unless a finding already
// shows it affected.
func stateOf(present map[string]*presence, byKey map[key][]match.Finding, k key) State {
	p := present[k.catName]
	if p == nil {
		return StateAbsent
	}
	findings := byKey[k]
	if len(findings) == 0 {
		if p.unchecked {
			return StateUnchecked
		}
		return StateClean
	}
	worst := findings[0].Status
	for _, f := range findings[1:] {
		if match.Severity(f.Status) < match.Severity(worst) {
			worst = f.Status
		}
	}
	if worst != match.StatusAffected && p.unchecked {
		return StateUnchecked
	}
	return State(worst)
}

func versionsOf(p *presence) []string {
	out := []string{}
	if p == nil {
		return out
	}
	for v := range p.versions {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// collect returns the sorted, deduplicated, non-empty values of field.
func collect(findings []match.Finding, field func(match.Finding) string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, f := range findings {
		if v := field(f); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func skippedOf(in []sbom.SkippedPackage) []Skipped {
	out := make([]Skipped, 0, len(in))
	for _, s := range in {
		out = append(out, Skipped{Name: s.Name, Version: s.Version, PURL: s.PURL, Reason: s.Reason, Ecosystem: s.Ecosystem, Module: s.Module})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].PURL < out[j].PURL
	})
	return out
}
