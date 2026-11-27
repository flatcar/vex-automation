// Package diff compares the vulnerability findings of two SBOMs (an older
// and a newer Flatcar release) matched against the same vulnerability data,
// and classifies each (vulnerability, package) pair as fixed, removed,
// introduced, still affected or needing review. It is pure logic: loading
// SBOMs and running the matchers is up to the caller (cli.runDiff).
//
// Its main use is drafting the "Security fixes" section of the release
// notes (FormatChangelog), so it errs towards "review" whenever a side
// couldn't be fully checked: a wrong "fixed" line would be published as a
// claim about the release.
package diff

import (
	"cmp"
	"maps"
	"slices"

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
var bucketOrder = []Bucket{BucketFixed, BucketRemoved, BucketIntroduced, BucketStillAffected, BucketReview}

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
	Package    string         `json:"package"`
	Ecosystem  sbom.Ecosystem `json:"ecosystem"`
	Old        SideInfo       `json:"old"`
	New        SideInfo       `json:"new"`
	Sources    []string       `json:"sources"`
	Advisories []string       `json:"advisories"`
	Notes      []string       `json:"notes"`
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
	Ecosystem sbom.Ecosystem `json:"ecosystem,omitempty"`
	Module    string         `json:"module,omitempty"`
}

// key identifies one entry: a vulnerability in a package.
type key struct {
	id  string
	pkg packageID
}

// packageID identifies a package regardless of its version. The ecosystem
// is part of it because packages of different ecosystems may share a name.
type packageID struct {
	ecosystem sbom.Ecosystem
	name      string // sbom.Package.FullName()
}

func idOf(pkg sbom.Package) packageID {
	return packageID{ecosystem: pkg.Ecosystem, name: pkg.FullName()}
}

// presence is what one release ships of one package.
type presence struct {
	versions map[string]bool
	// unchecked is set if some copy has a version that couldn't be checked.
	unchecked bool
}

// comparedSide is one release, prepared for comparison.
type comparedSide struct {
	packages map[packageID]*presence
	findings map[key][]match.Finding
}

func prepare(s Side) comparedSide {
	return comparedSide{packages: packagesOf(s.Doc), findings: groupFindings(s.Findings)}
}

// Compute compares in.Old with in.New. The result doesn't depend on the
// order of packages or findings.
//
// It works on (vulnerability, package) keys rather than on whole
// vulnerabilities, because the release notes credit a fix to a package.
// For every key that has a finding on either side, it reduces each side
// to one State (stateOf) and turns the pair of states into a Bucket
// (classify).
func Compute(in Input) Result {
	oldSide, newSide := prepare(in.Old), prepare(in.New)
	keys := map[key]bool{}
	for k := range oldSide.findings {
		keys[k] = true
	}
	for k := range newSide.findings {
		keys[k] = true
	}

	entries := []Entry{}
	var summary Summary
	for k := range keys {
		entry, ok := compareKey(k, oldSide, newSide)
		if ok {
			entries = append(entries, entry)
			summary.add(entry.Bucket)
		}
	}
	slices.SortFunc(entries, func(a, b Entry) int {
		return cmp.Or(
			cmp.Compare(slices.Index(bucketOrder, a.Bucket), slices.Index(bucketOrder, b.Bucket)),
			cmp.Compare(a.Package, b.Package),
			cmp.Compare(a.Ecosystem, b.Ecosystem),
			cmp.Compare(a.ID, b.ID),
		)
	})

	return Result{
		SchemaVersion: SchemaVersion,
		Summary:       summary,
		Entries:       entries,
		NotChecked:    NotChecked{Old: skippedOf(in.Old.Doc.Skipped), New: skippedOf(in.New.Doc.Skipped)},
	}
}

// compareKey builds the entry for k. ok is false if k is not worth
// reporting, e.g. because it is fixed on both sides.
func compareKey(k key, oldSide, newSide comparedSide) (Entry, bool) {
	oldState, newState := oldSide.stateOf(k), newSide.stateOf(k)
	bucket, ok := classify(oldState, newState)
	if !ok {
		return Entry{}, false
	}

	var sources, advisories, notes []string
	for _, finding := range append(slices.Clone(oldSide.findings[k]), newSide.findings[k]...) {
		sources = append(sources, finding.Source)
		advisories = append(advisories, finding.RefID)
		notes = append(notes, finding.Note)
	}
	return Entry{
		ID:         k.id,
		Bucket:     bucket,
		Package:    k.pkg.name,
		Ecosystem:  k.pkg.ecosystem,
		Old:        SideInfo{State: oldState, Versions: versionsOf(oldSide.packages[k.pkg])},
		New:        SideInfo{State: newState, Versions: versionsOf(newSide.packages[k.pkg])},
		Sources:    sortedNonEmpty(sources),
		Advisories: sortedNonEmpty(advisories),
		Notes:      sortedNonEmpty(notes),
	}, true
}

// classify applies the bucket rules in order. ok is false for changes not
// worth reporting.
func classify(oldState, newState State) (Bucket, bool) {
	switch {
	case oldState == StateAffected && (newState == StateFixed || newState == StateNotAffected || newState == StateClean):
		return BucketFixed, true
	case oldState == StateAffected && newState == StateAbsent:
		return BucketRemoved, true
	case oldState == StateAffected && newState == StateAffected:
		return BucketStillAffected, true
	case isUnknown(oldState) || isUnknown(newState):
		// Checked before "introduced": an old state that couldn't be
		// evaluated doesn't show the vulnerability is new.
		return BucketReview, true
	case newState == StateAffected:
		return BucketIntroduced, true
	}
	return "", false
}

func isUnknown(s State) bool {
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

// stateOf returns the state of k on this side: the most severe status of
// its findings. A copy that couldn't be checked makes it unchecked, unless
// a finding already shows it affected.
func (s comparedSide) stateOf(k key) State {
	pkg := s.packages[k.pkg]
	if pkg == nil {
		return StateAbsent
	}
	findings := s.findings[k]
	if len(findings) == 0 {
		if pkg.unchecked {
			return StateUnchecked
		}
		return StateClean
	}
	worst := slices.MinFunc(findings, func(a, b match.Finding) int {
		return match.Severity(a.Status) - match.Severity(b.Status)
	}).Status
	if worst != match.StatusAffected && pkg.unchecked {
		return StateUnchecked
	}
	return State(worst)
}

// packagesOf lists what doc ships, including copies that couldn't be checked.
func packagesOf(doc sbom.Document) map[packageID]*presence {
	packages := map[packageID]*presence{}
	for _, pkg := range slices.Concat(doc.Ebuilds, doc.Modules) {
		addPresence(packages, pkg)
	}
	for _, skipped := range doc.Skipped {
		if skipped.Module != "" {
			pkg := sbom.Package{Ecosystem: skipped.Ecosystem, Name: skipped.Module, Version: skipped.Version}
			addPresence(packages, pkg).unchecked = true
		}
	}
	return packages
}

func addPresence(packages map[packageID]*presence, pkg sbom.Package) *presence {
	entry := packages[idOf(pkg)]
	if entry == nil {
		entry = &presence{versions: map[string]bool{}}
		packages[idOf(pkg)] = entry
	}
	entry.versions[pkg.Version] = true
	return entry
}

func groupFindings(findings []match.Finding) map[key][]match.Finding {
	grouped := map[key][]match.Finding{}
	for _, finding := range findings {
		k := key{id: finding.CVE, pkg: idOf(finding.Package)}
		grouped[k] = append(grouped[k], finding)
	}
	return grouped
}

// versionsOf returns the sorted versions shipped, or an empty list (which
// encodes as [] rather than null in JSON).
func versionsOf(pkg *presence) []string {
	if pkg == nil {
		return []string{}
	}
	return slices.Sorted(maps.Keys(pkg.versions))
}

// sortedNonEmpty returns the distinct non-empty values, sorted. The result
// is never nil, so that it encodes as [] in JSON.
func sortedNonEmpty(values []string) []string {
	result := []string{}
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func skippedOf(packages []sbom.SkippedPackage) []Skipped {
	skipped := make([]Skipped, len(packages))
	for i, pkg := range packages {
		skipped[i] = Skipped{
			Name: pkg.Name, Version: pkg.Version, PURL: pkg.PURL, Reason: pkg.Reason,
			Ecosystem: pkg.Ecosystem, Module: pkg.Module,
		}
	}
	slices.SortFunc(skipped, func(a, b Skipped) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Version, b.Version), cmp.Compare(a.PURL, b.PURL))
	})
	return skipped
}
