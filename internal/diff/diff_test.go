package diff

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/flatcar/vex-automation/internal/match"
	"github.com/flatcar/vex-automation/internal/sbom"
)

func ebuild(catName, version string) sbom.Package {
	cat, name, _ := strings.Cut(catName, "/")
	return sbom.Package{Category: cat, Name: name, Version: version, PURL: "pkg:ebuild/" + catName + "@" + version}
}

func gomod(module, version string) sbom.Package {
	return sbom.Package{Category: "golang", Name: module, Version: version, PURL: "pkg:golang/" + module + "@" + version}
}

func glsaFinding(id string, pkg sbom.Package, status match.Status, ref string) match.Finding {
	return match.Finding{CVE: id, Source: match.SourceGLSA, RefID: ref, Package: pkg, Status: status}
}

func osvFinding(id string, pkg sbom.Package, ref string) match.Finding {
	return match.Finding{CVE: id, Source: match.SourceOSV, RefID: ref, Package: pkg, Status: match.StatusAffected}
}

func side(pkgs []sbom.Package, findings ...match.Finding) Side {
	var doc sbom.Document
	for _, p := range pkgs {
		if p.Category == "golang" || p.Category == "cargo" {
			doc.OSVPackages = append(doc.OSVPackages, p)
		} else {
			doc.Packages = append(doc.Packages, p)
		}
	}
	return Side{Doc: doc, Findings: findings}
}

func TestComputeBuckets(t *testing.T) {
	fuseOld, fuseNew := ebuild("sys-fs/fuse", "3.17.0"), ebuild("sys-fs/fuse", "3.18.1")
	modOld, modNew := gomod("example.com/mod", "v1.0.0"), gomod("example.com/mod", "v1.1.0")

	tests := []struct {
		name     string
		old, new Side
		want     []Entry
	}{
		{
			name: "GLSA affected then fixed",
			old:  side([]sbom.Package{fuseOld}, glsaFinding("CVE-1", fuseOld, match.StatusAffected, "202604-03")),
			new:  side([]sbom.Package{fuseNew}, glsaFinding("CVE-1", fuseNew, match.StatusFixed, "202604-03")),
			want: []Entry{{
				ID: "CVE-1", Bucket: BucketFixed, Package: "sys-fs/fuse", Ecosystem: "ebuild",
				Old:     SideInfo{State: StateAffected, Versions: []string{"3.17.0"}},
				New:     SideInfo{State: StateFixed, Versions: []string{"3.18.1"}},
				Sources: []string{"glsa"}, Advisories: []string{"202604-03"}, Notes: []string{},
			}},
		},
		{
			name: "OSV affected then clean",
			old:  side([]sbom.Package{modOld}, osvFinding("CVE-2", modOld, "GHSA-x")),
			new:  side([]sbom.Package{modNew}),
			want: []Entry{{
				ID: "CVE-2", Bucket: BucketFixed, Package: "example.com/mod", Ecosystem: "golang",
				Old:     SideInfo{State: StateAffected, Versions: []string{"v1.0.0"}},
				New:     SideInfo{State: StateClean, Versions: []string{"v1.1.0"}},
				Sources: []string{"osv"}, Advisories: []string{"GHSA-x"}, Notes: []string{},
			}},
		},
		{
			name: "package removed",
			old:  side([]sbom.Package{modOld}, osvFinding("CVE-3", modOld, "GO-1")),
			new:  side(nil),
			want: []Entry{{
				ID: "CVE-3", Bucket: BucketRemoved, Package: "example.com/mod", Ecosystem: "golang",
				Old:     SideInfo{State: StateAffected, Versions: []string{"v1.0.0"}},
				New:     SideInfo{State: StateAbsent, Versions: []string{}},
				Sources: []string{"osv"}, Advisories: []string{"GO-1"}, Notes: []string{},
			}},
		},
		{
			name: "introduced from absent",
			old:  side(nil),
			new:  side([]sbom.Package{modNew}, osvFinding("CVE-4", modNew, "GO-2")),
			want: []Entry{{
				ID: "CVE-4", Bucket: BucketIntroduced, Package: "example.com/mod", Ecosystem: "golang",
				Old:     SideInfo{State: StateAbsent, Versions: []string{}},
				New:     SideInfo{State: StateAffected, Versions: []string{"v1.1.0"}},
				Sources: []string{"osv"}, Advisories: []string{"GO-2"}, Notes: []string{},
			}},
		},
		{
			name: "introduced from clean",
			old:  side([]sbom.Package{modOld}),
			new:  side([]sbom.Package{modNew}, osvFinding("CVE-4", modNew, "GO-2")),
			want: []Entry{{
				ID: "CVE-4", Bucket: BucketIntroduced, Package: "example.com/mod", Ecosystem: "golang",
				Old:     SideInfo{State: StateClean, Versions: []string{"v1.0.0"}},
				New:     SideInfo{State: StateAffected, Versions: []string{"v1.1.0"}},
				Sources: []string{"osv"}, Advisories: []string{"GO-2"}, Notes: []string{},
			}},
		},
		{
			name: "still affected",
			old:  side([]sbom.Package{fuseOld}, glsaFinding("CVE-5", fuseOld, match.StatusAffected, "1")),
			new:  side([]sbom.Package{fuseNew}, glsaFinding("CVE-5", fuseNew, match.StatusAffected, "1")),
			want: []Entry{{
				ID: "CVE-5", Bucket: BucketStillAffected, Package: "sys-fs/fuse", Ecosystem: "ebuild",
				Old:     SideInfo{State: StateAffected, Versions: []string{"3.17.0"}},
				New:     SideInfo{State: StateAffected, Versions: []string{"3.18.1"}},
				Sources: []string{"glsa"}, Advisories: []string{"1"}, Notes: []string{},
			}},
		},
		{
			name: "under investigation goes to review with its note",
			old: side([]sbom.Package{fuseOld}, match.Finding{
				CVE: "CVE-6", Source: match.SourceGLSA, RefID: "1", Package: fuseOld,
				Status: match.StatusUnderInvestigation, Note: "slot",
			}),
			new: side([]sbom.Package{fuseNew}, glsaFinding("CVE-6", fuseNew, match.StatusFixed, "1")),
			want: []Entry{{
				ID: "CVE-6", Bucket: BucketReview, Package: "sys-fs/fuse", Ecosystem: "ebuild",
				Old:     SideInfo{State: StateUnderInvestigation, Versions: []string{"3.17.0"}},
				New:     SideInfo{State: StateFixed, Versions: []string{"3.18.1"}},
				Sources: []string{"glsa"}, Advisories: []string{"1"}, Notes: []string{"slot"},
			}},
		},
		{
			name: "fixed on both sides is not reported",
			old:  side([]sbom.Package{fuseOld}, glsaFinding("CVE-7", fuseOld, match.StatusFixed, "1")),
			new:  side([]sbom.Package{fuseNew}, glsaFinding("CVE-7", fuseNew, match.StatusFixed, "1")),
			want: []Entry{},
		},
		{
			name: "one affected copy among several makes the side affected",
			old: side([]sbom.Package{modOld, gomod("example.com/mod", "v1.2.0")},
				osvFinding("CVE-8", modOld, "GO-8")),
			new: side([]sbom.Package{modNew}),
			want: []Entry{{
				ID: "CVE-8", Bucket: BucketFixed, Package: "example.com/mod", Ecosystem: "golang",
				Old:     SideInfo{State: StateAffected, Versions: []string{"v1.0.0", "v1.2.0"}},
				New:     SideInfo{State: StateClean, Versions: []string{"v1.1.0"}},
				Sources: []string{"osv"}, Advisories: []string{"GO-8"}, Notes: []string{},
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Compute(Input{Old: tc.old, New: tc.new})
			if !reflect.DeepEqual(got.Entries, tc.want) {
				g, _ := json.MarshalIndent(got.Entries, "", "  ")
				w, _ := json.MarshalIndent(tc.want, "", "  ")
				t.Fatalf("entries mismatch\ngot:  %s\nwant: %s", g, w)
			}
		})
	}
}

func TestComputeSummaryAndOrder(t *testing.T) {
	a, b := ebuild("net-misc/curl", "8.0"), ebuild("net-misc/curl", "8.1")
	z := gomod("z.example/mod", "v1")
	old := side([]sbom.Package{a, z},
		glsaFinding("CVE-B", a, match.StatusAffected, "1"),
		glsaFinding("CVE-A", a, match.StatusAffected, "1"),
		osvFinding("CVE-Z", z, "GO-Z"),
	)
	nw := side([]sbom.Package{b}, glsaFinding("CVE-C", b, match.StatusAffected, "2"))

	got := Compute(Input{Old: old, New: nw})

	var order []string
	for _, e := range got.Entries {
		order = append(order, string(e.Bucket)+":"+e.Package+":"+e.ID)
	}
	want := []string{
		"fixed:net-misc/curl:CVE-A",
		"fixed:net-misc/curl:CVE-B",
		"removed:z.example/mod:CVE-Z",
		"introduced:net-misc/curl:CVE-C",
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	wantSummary := Summary{Fixed: 2, Removed: 1, Introduced: 1}
	if got.Summary != wantSummary {
		t.Fatalf("summary = %+v, want %+v", got.Summary, wantSummary)
	}
}

func TestComputeIsDeterministic(t *testing.T) {
	var pkgs []sbom.Package
	var findings []match.Finding
	for i, v := range []string{"v1", "v2", "v3", "v4", "v5"} {
		p := gomod("example.com/m"+v, v)
		pkgs = append(pkgs, p)
		findings = append(findings, osvFinding("CVE-"+v, p, "GO-"+v), osvFinding("CVE-x", p, "GO-x"))
		if i%2 == 0 {
			findings = append(findings, glsaFinding("CVE-y", p, match.StatusFixed, "9"))
		}
	}
	first, _ := json.Marshal(Compute(Input{Old: side(pkgs, findings...), New: side(nil)}))

	rng := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic shuffle for a test.
	for range 20 {
		rng.Shuffle(len(findings), func(i, j int) { findings[i], findings[j] = findings[j], findings[i] })
		rng.Shuffle(len(pkgs), func(i, j int) { pkgs[i], pkgs[j] = pkgs[j], pkgs[i] })
		got, _ := json.Marshal(Compute(Input{Old: side(pkgs, findings...), New: side(nil)}))
		if string(got) != string(first) {
			t.Fatalf("non-deterministic output:\n%s\n%s", first, got)
		}
	}
}

func TestComputeNotCheckedAndEmptySlices(t *testing.T) {
	old := side(nil)
	old.Doc.Skipped = []sbom.SkippedPackage{{Name: "linux-kernel", Version: "6.12", PURL: "pkg:generic/linux-kernel@6.12", Reason: "unsupported purl type"}}

	got := Compute(Input{Old: old, New: side(nil)})
	out, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":1,"tooling":"","old":{"sbom_name":"","product_id":""},"new":{"sbom_name":"","product_id":""},` +
		`"summary":{"fixed":0,"removed":0,"introduced":0,"still_affected":0,"review":0},"entries":[],` +
		`"not_checked":{"old":[{"name":"linux-kernel","version":"6.12","purl":"pkg:generic/linux-kernel@6.12","reason":"unsupported purl type"}],"new":[],"osv_disabled":false}}`
	if string(out) != want {
		t.Fatalf("JSON =\n%s\nwant\n%s", out, want)
	}
}

// An old state that could not be evaluated says nothing about whether the
// vulnerability is new, so it must not be reported as introduced.
func TestComputeUnderInvestigationThenAffectedIsReview(t *testing.T) {
	fuseOld, fuseNew := ebuild("sys-fs/fuse", "3.17.0"), ebuild("sys-fs/fuse", "3.18.1")
	got := Compute(Input{
		Old: side([]sbom.Package{fuseOld}, match.Finding{CVE: "CVE-1", Source: match.SourceGLSA, RefID: "1", Package: fuseOld, Status: match.StatusUnderInvestigation}),
		New: side([]sbom.Package{fuseNew}, glsaFinding("CVE-1", fuseNew, match.StatusAffected, "1")),
	})
	if len(got.Entries) != 1 || got.Entries[0].Bucket != BucketReview {
		t.Fatalf("entries = %+v, want one review entry", got.Entries)
	}
}

// A module copy whose version can't be queried (e.g. "(devel)") may still be
// affected, so a side with such a copy can't prove a fix or a removal; it
// can still prove the module affected through another copy.
func TestComputeUncheckedCopies(t *testing.T) {
	modOld, modNew := gomod("example.com/mod", "v1.0.0"), gomod("example.com/mod", "v1.1.0")
	unchecked := sbom.SkippedPackage{Name: "example.com/mod", Version: "(devel)", PURL: "pkg:golang/example.com/mod@(devel)",
		Reason: "version is not queryable", Ecosystem: "golang", Module: "example.com/mod"}
	withUnchecked := func(s Side) Side {
		s.Doc.Skipped = append(s.Doc.Skipped, unchecked)
		return s
	}

	tests := []struct {
		name      string
		old, new  Side
		wantState State
		want      Bucket
	}{
		{"clean copy next to an unchecked one is not a fix",
			side([]sbom.Package{modOld}, osvFinding("CVE-1", modOld, "GO-1")),
			withUnchecked(side([]sbom.Package{modNew})), StateUnchecked, BucketReview},
		{"only an unchecked copy left is not a removal",
			side([]sbom.Package{modOld}, osvFinding("CVE-1", modOld, "GO-1")),
			withUnchecked(side(nil)), StateUnchecked, BucketReview},
		{"an affected copy still makes the side affected",
			side([]sbom.Package{modOld}, osvFinding("CVE-1", modOld, "GO-1")),
			withUnchecked(side([]sbom.Package{modNew}, osvFinding("CVE-1", modNew, "GO-1"))), StateAffected, BucketStillAffected},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Compute(Input{Old: tc.old, New: tc.new})
			if len(got.Entries) != 1 || got.Entries[0].Bucket != tc.want || got.Entries[0].New.State != tc.wantState {
				t.Fatalf("entries = %+v, want one %s entry with new state %s", got.Entries, tc.want, tc.wantState)
			}
		})
	}
}
