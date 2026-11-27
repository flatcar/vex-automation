package match

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/flatcar/vex-automation/internal/glsa"
	"github.com/flatcar/vex-automation/internal/osv"
	"github.com/flatcar/vex-automation/internal/sbom"
)

func fuseGLSA() glsa.GLSA {
	return glsa.GLSA{
		ID:   "202604-03",
		CVEs: []string{"CVE-2026-33150", "CVE-2026-33179"},
		Packages: []glsa.AffectedPackage{
			{
				CategoryName: "sys-fs/fuse",
				Arch:         "*",
				Unaffected:   []glsa.VersionRange{{Op: "ge", Version: "3.18.1"}},
				Vulnerable:   []glsa.VersionRange{{Op: "lt", Version: "3.18.1"}},
			},
		},
	}
}

func TestRunAffected(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
	}

	findings := RunGLSA(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per CVE): %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Status != StatusAffected {
			t.Errorf("finding %+v: want Status=affected for version below the unaffected range", f)
		}
		if f.Source != SourceGLSA {
			t.Errorf("Source = %q, want %q", f.Source, SourceGLSA)
		}
		if f.RefID != "202604-03" {
			t.Errorf("RefID = %q, want 202604-03", f.RefID)
		}
	}
	// Sorted by CVE.
	if findings[0].CVE != "CVE-2026-33150" || findings[1].CVE != "CVE-2026-33179" {
		t.Errorf("findings not sorted by CVE: %+v", findings)
	}
}

func TestRunFixed(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "3.18.1", PURL: "pkg:ebuild/sys-fs/fuse@3.18.1"},
	}

	findings := RunGLSA(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.Status != StatusFixed {
			t.Errorf("finding %+v: want Status=fixed for version at the unaffected boundary", f)
		}
	}
}

func TestRunNoMatchingPackage(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-apps", Name: "systemd", Version: "255.4-r2", PURL: "pkg:ebuild/sys-apps/systemd@255.4-r2"},
	}

	findings := RunGLSA(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 for an unrelated package", len(findings))
	}
}

func TestRunArchMismatch(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
	}
	g := fuseGLSA()
	g.Packages[0].Arch = "arm64"

	findings := RunGLSA(pkgs, []glsa.GLSA{g}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 when GLSA arch doesn't match", len(findings))
	}
}

// An unparseable installed version must not make the vulnerability vanish
// from the VEX document: it is reported as under investigation.
func TestRunUnparseableVersionIsUnderInvestigation(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "not-a-version!!", PURL: "pkg:ebuild/sys-fs/fuse@bogus"},
	}

	findings := RunGLSA(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Status != StatusUnderInvestigation || f.Note == "" {
			t.Errorf("finding %+v: want Status=under_investigation with a note", f)
		}
	}
}

func TestRunGLSAWithNoCVEsUsesGLSAID(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
	}
	g := fuseGLSA()
	g.CVEs = nil

	findings := RunGLSA(pkgs, []glsa.GLSA{g}, "amd64")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 for a GLSA with no CVE references: %+v", len(findings), findings)
	}
	if findings[0].CVE != "GLSA-202604-03" || findings[0].Status != StatusAffected {
		t.Errorf("finding = %+v, want CVE=GLSA-202604-03 Status=affected", findings[0])
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		vulnerable []glsa.VersionRange
		unaffected []glsa.VersionRange
		want       Status
	}{
		{
			// Regression: the vulnerable range also covers fixed revisions
			// of an older branch. Installed 1.5 is not >=~1.0-r1 (different
			// base version), so it is affected, not fixed.
			name:       "revision op only covers its own base version",
			version:    "1.5",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "2.0"}},
			unaffected: []glsa.VersionRange{{Op: "ge", Version: "2.0"}, {Op: "rge", Version: "1.0-r1"}},
			want:       StatusAffected,
		},
		{
			name:       "revision op matches a fixed revision",
			version:    "1.0-r2",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "2.0"}},
			unaffected: []glsa.VersionRange{{Op: "ge", Version: "2.0"}, {Op: "rge", Version: "1.0-r1"}},
			want:       StatusFixed,
		},
		{
			name:       "outside every range is not affected",
			version:    "1.3",
			vulnerable: []glsa.VersionRange{{Op: "eq", Version: "1.2*"}},
			unaffected: []glsa.VersionRange{{Op: "ge", Version: "1.4"}},
			want:       StatusNotAffected,
		},
		{
			// Regression: a numeric slot is matched against the installed
			// version's branch, so 3.12.1 is checked against the 3.12
			// ranges only and the 3.11 "ge 3.11.9" range doesn't fix it.
			name:    "numeric slots select the matching branch",
			version: "3.12.1",
			vulnerable: []glsa.VersionRange{
				{Op: "lt", Version: "3.11.9", Slot: "3.11"},
				{Op: "lt", Version: "3.12.4", Slot: "3.12"},
			},
			unaffected: []glsa.VersionRange{
				{Op: "ge", Version: "3.11.9", Slot: "3.11"},
				{Op: "ge", Version: "3.12.4", Slot: "3.12"},
			},
			want: StatusAffected,
		},
		{
			name:       "numeric slot prefix must end at a component boundary",
			version:    "17.0.1",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "17.0.2", Slot: "17"}},
			// Would make 17.0.1 fixed if slot "1" were taken as its branch.
			unaffected: []glsa.VersionRange{{Op: "ge", Version: "17.0.0", Slot: "1"}},
			want:       StatusAffected,
		},
		{
			// Regression: webkit-gtk uses slots "4"/"6" for 2.x versions,
			// so a numeric slot that isn't the installed branch must not be
			// silently ruled out.
			name:       "numeric slots that don't follow the version are unknown",
			version:    "2.44.0",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "2.44.2", Slot: "4"}},
			unaffected: []glsa.VersionRange{{Op: "ge", Version: "2.44.2", Slot: "4"}},
			want:       StatusUnderInvestigation,
		},
		{
			// Regression: a fix in an unknown slot doesn't show the
			// installed version is fixed; in another slot it is not affected.
			name:       "newer than a fix in an unknown slot",
			version:    "2.45.0",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "2.44.2", Slot: "4"}},
			unaffected: []glsa.VersionRange{{Op: "ge", Version: "2.44.2", Slot: "4"}},
			want:       StatusUnderInvestigation,
		},
		{
			name:       "newer than a revision-restricted fix in an unknown slot",
			version:    "2.45.0",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "2.44.2", Slot: "4"}},
			unaffected: []glsa.VersionRange{{Op: "rge", Version: "2.44.2", Slot: "4"}},
			want:       StatusUnderInvestigation,
		},
		{
			name:       "fix in an applicable range outweighs one in an unknown slot",
			version:    "2.45.0",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "2.44.2"}},
			unaffected: []glsa.VersionRange{{Op: "ge", Version: "2.44.2", Slot: "4"}, {Op: "rge", Version: "2.44.2"}},
			want:       StatusFixed,
		},
		{
			name:    "other branch's slot is ruled out when the installed branch is listed",
			version: "3.12.5",
			// The 3.11 range would match 3.12.5 if its slot were ignored.
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "3.13", Slot: "3.11"}, {Op: "lt", Version: "3.12.4", Slot: "3.12"}},
			want:       StatusNotAffected,
		},
		{
			name:       "named slot that could change the answer",
			version:    "115.0",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "115.9", Slot: "esr"}},
			unaffected: []glsa.VersionRange{{Op: "ge", Version: "115.9", Slot: "esr"}},
			want:       StatusUnderInvestigation,
		},
		{
			name:       "named slot that could change the answer next to an unslotted range",
			version:    "120.0",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "125.0", Slot: "esr"}},
			unaffected: []glsa.VersionRange{{Op: "ge", Version: "130.0"}},
			want:       StatusUnderInvestigation,
		},
		{
			name:       "named slot range that doesn't match is irrelevant",
			version:    "120.0",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "110.0"}, {Op: "lt", Version: "115.9", Slot: "esr"}},
			unaffected: []glsa.VersionRange{{Op: "ge", Version: "130.0"}},
			want:       StatusNotAffected,
		},
		{
			// Regression: a newer branch than every rge fix matches no
			// range, and was reported as never having had the vulnerable
			// code (GLSA 202003-52 vs samba 4.22.5).
			name:       "newer than a revision-restricted fix",
			version:    "4.22.5-r1",
			vulnerable: []glsa.VersionRange{{Op: "lt", Version: "4.11.6"}},
			unaffected: []glsa.VersionRange{
				{Op: "rge", Version: "4.9.18"},
				{Op: "rge", Version: "4.11.6"},
			},
			want: StatusFixed,
		},
		{
			name:       "older than every vulnerable range",
			version:    "1.0",
			vulnerable: []glsa.VersionRange{{Op: "rlt", Version: "2.0-r3"}},
			unaffected: []glsa.VersionRange{{Op: "rge", Version: "2.0-r3"}},
			want:       StatusNotAffected,
		},
		{
			name:       "glob range",
			version:    "2.4.7-r1",
			vulnerable: []glsa.VersionRange{{Op: "eq", Version: "2.4*"}},
			want:       StatusAffected,
		},
		{
			name:       "unknown operator",
			version:    "1.0",
			vulnerable: []glsa.VersionRange{{Op: "bogus", Version: "2.0"}},
			want:       StatusUnderInvestigation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, note := evaluate(tt.version, glsa.AffectedPackage{Vulnerable: tt.vulnerable, Unaffected: tt.unaffected})
			if got != tt.want {
				t.Errorf("evaluate(%q) = %q (%s), want %q", tt.version, got, note, tt.want)
			}
			if got == StatusUnderInvestigation && note == "" {
				t.Error("under_investigation result has no note")
			}
		})
	}
}

// newOSVTestClient starts an httptest.Server that answers querybatch/vulns
// requests from a fixed map of "pkg:<type>/<name>@<version>" ->
// vulnerability IDs, plus vuln ID -> alias, and returns an *osv.Client
// pointed at it. Like OSV.dev, it lowercases purl queries, while
// name/ecosystem queries are matched case-sensitively.
func newOSVTestClient(t *testing.T, vulnsByPurl map[string][]string, aliasesByID map[string][]string) *osv.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct {
					PURL      string `json:"purl"`
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding querybatch request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		type vuln struct {
			ID string `json:"id"`
		}
		type result struct {
			Vulns []vuln `json:"vulns"`
		}
		var resp struct {
			Results []result `json:"results"`
		}
		for _, q := range req.Queries {
			var vulns []vuln
			key := strings.ToLower(q.Package.PURL)
			if key == "" {
				typ := map[string]string{"Go": "golang", "crates.io": "cargo"}[q.Package.Ecosystem]
				key = "pkg:" + typ + "/" + q.Package.Name + "@" + q.Version
			}
			for _, id := range vulnsByPurl[key] {
				vulns = append(vulns, vuln{ID: id})
			}
			resp.Results = append(resp.Results, result{Vulns: vulns})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		_ = json.NewEncoder(w).Encode(struct {
			ID      string   `json:"id"`
			Aliases []string `json:"aliases"`
		}{ID: id, Aliases: aliasesByID[id]})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &osv.Client{BaseURL: srv.URL}
}

func TestRunOSVBuildsFindingsFromResults(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "golang", Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
	}
	client := newOSVTestClient(t,
		map[string][]string{"pkg:golang/example.com/mod@v1.0.0": {"GHSA-aaaa"}},
		map[string][]string{"GHSA-aaaa": {"CVE-2026-9999"}},
	)

	findings, err := RunOSV(context.Background(), pkgs, client)
	if err != nil {
		t.Fatalf("RunOSV returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.CVE != "CVE-2026-9999" {
		t.Errorf("CVE = %q, want CVE-2026-9999", f.CVE)
	}
	if f.Source != SourceOSV {
		t.Errorf("Source = %q, want %q", f.Source, SourceOSV)
	}
	if f.RefID != "GHSA-aaaa" {
		t.Errorf("RefID = %q, want GHSA-aaaa", f.RefID)
	}
	if f.Status != StatusAffected {
		t.Errorf("Status = %q, want affected for an OSV.dev finding", f.Status)
	}
	if f.Package.PURL != "pkg:golang/example.com/mod@v1.0.0" {
		t.Errorf("Package.PURL = %q, want the original SBOM purl preserved", f.Package.PURL)
	}
}

// A single OSV.dev record can alias several CVEs; each must become a
// finding, not just the first.
func TestRunOSVReportsEveryCVEAlias(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "golang", Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
	}
	client := newOSVTestClient(t,
		map[string][]string{"pkg:golang/example.com/mod@v1.0.0": {"GO-2026-1"}},
		map[string][]string{"GO-2026-1": {"CVE-2026-2", "GHSA-x", "CVE-2026-1"}},
	)

	findings, err := RunOSV(context.Background(), pkgs, client)
	if err != nil {
		t.Fatalf("RunOSV returned error: %v", err)
	}
	if len(findings) != 2 || findings[0].CVE != "CVE-2026-1" || findings[1].CVE != "CVE-2026-2" {
		t.Fatalf("findings = %+v, want CVE-2026-1 and CVE-2026-2", findings)
	}
	for _, f := range findings {
		if f.RefID != "GO-2026-1" {
			t.Errorf("RefID = %q, want GO-2026-1", f.RefID)
		}
	}
}

// A GHSA and a GO record without a CVE that alias each other describe one
// vulnerability and must be reported once (as seen with grpc's
// GHSA-hrxh-6v49-42gf / GO-2026-6061).
func TestRunOSVReportsAliasedRecordsWithoutCVEOnce(t *testing.T) {
	// The alias may be recorded on either side only.
	for name, aliases := range map[string]map[string][]string{
		"GO lists GHSA": {"GO-2026-1": {"GHSA-aaaa"}},
		"GHSA lists GO": {"GHSA-aaaa": {"GO-2026-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			pkgs := []sbom.Package{
				{Category: "golang", Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
			}
			client := newOSVTestClient(t,
				map[string][]string{"pkg:golang/example.com/mod@v1.0.0": {"GO-2026-1", "GHSA-aaaa", "GO-2026-2"}},
				aliases,
			)

			findings, err := RunOSV(context.Background(), pkgs, client)
			if err != nil {
				t.Fatalf("RunOSV returned error: %v", err)
			}
			var got []string
			for _, f := range findings {
				got = append(got, f.CVE)
			}
			if want := []string{"GHSA-aaaa", "GO-2026-2"}; !slices.Equal(got, want) {
				t.Fatalf("findings = %v, want %v", got, want)
			}
		})
	}
}

// Aliased CVE-less records get one ID across all queried packages: if one
// version returns both records and another only one of them, both must
// still report the same ID, or a diff would see a fix plus a new
// vulnerability. RefID keeps the record actually returned.
func TestRunOSVCanonicalizesAliasedRecordsAcrossPackages(t *testing.T) {
	for name, aliases := range map[string]map[string][]string{
		"GO lists GHSA": {"GO-2026-1": {"GHSA-aaaa"}},
		"GHSA lists GO": {"GHSA-aaaa": {"GO-2026-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			pkgs := []sbom.Package{
				{Category: "golang", Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
				{Category: "golang", Name: "example.com/mod", Version: "v1.1.0", PURL: "pkg:golang/example.com/mod@v1.1.0"},
			}
			client := newOSVTestClient(t, map[string][]string{
				"pkg:golang/example.com/mod@v1.0.0": {"GO-2026-1", "GHSA-aaaa"},
				"pkg:golang/example.com/mod@v1.1.0": {"GO-2026-1"},
			}, aliases)

			findings, err := RunOSV(context.Background(), pkgs, client)
			if err != nil {
				t.Fatalf("RunOSV returned error: %v", err)
			}
			var got []string
			for _, f := range findings {
				got = append(got, f.Package.Version+" "+f.CVE+" "+f.RefID)
			}
			want := []string{"v1.0.0 GHSA-aaaa GHSA-aaaa", "v1.1.0 GHSA-aaaa GO-2026-1"}
			if !slices.Equal(got, want) {
				t.Fatalf("findings = %v, want %v", got, want)
			}
		})
	}
}

// The query must use the module path and version as normalized by
// sbom.Load (see sbom.TestLoad for the subpath and stdlib cases), keep its
// case (OSV.dev lowercases purl queries, so a mixed-case module path like
// github.com/Azure/... used to match nothing), and the VEX must keep the
// original SBOM purl.
func TestRunOSVQueriesNormalizedModuleAndVersion(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "golang", Name: "github.com/golang-jwt/jwt/v4", Version: "v4.5.1", PURL: "pkg:golang/github.com/golang-jwt/jwt@v4.5.1#v4"},
		{Category: "golang", Name: "stdlib", Version: "1.25.3", PURL: "pkg:golang/stdlib@1.25.3"},
		{Category: "golang", Name: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Version: "v1.5.0", PURL: "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.5.0"},
		{Category: "cargo", Name: "smallvec", Version: "1.6.0", PURL: "pkg:cargo/smallvec@1.6.0"},
	}
	client := newOSVTestClient(t,
		map[string][]string{
			"pkg:golang/github.com/golang-jwt/jwt/v4@v4.5.1":                     {"GO-1"},
			"pkg:golang/stdlib@1.25.3":                                           {"GO-2"},
			"pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.5.0": {"GO-3"},
			"pkg:cargo/smallvec@1.6.0":                                           {"RUSTSEC-1"},
		},
		map[string][]string{"GO-1": {"CVE-2026-1"}, "GO-2": {"CVE-2026-2"}, "GO-3": {"CVE-2024-35255"}, "RUSTSEC-1": {"CVE-2021-25900"}},
	)

	findings, err := RunOSV(context.Background(), pkgs, client)
	if err != nil {
		t.Fatalf("RunOSV returned error: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.CVE == "CVE-2026-1" && f.Package.PURL != "pkg:golang/github.com/golang-jwt/jwt@v4.5.1#v4" {
			t.Errorf("Package.PURL = %q, want the original SBOM purl", f.Package.PURL)
		}
	}
}

func TestRunOSVNoVulnerabilities(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "golang", Name: "example.com/safe", Version: "v1.0.0", PURL: "pkg:golang/example.com/safe@v1.0.0"},
	}
	client := newOSVTestClient(t, nil, nil)

	findings, err := RunOSV(context.Background(), pkgs, client)
	if err != nil {
		t.Fatalf("RunOSV returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestRunOSVEmptyPackages(t *testing.T) {
	findings, err := RunOSV(context.Background(), nil, &osv.Client{})
	if err != nil {
		t.Fatalf("RunOSV returned error: %v", err)
	}
	if findings != nil {
		t.Errorf("got %+v, want nil", findings)
	}
}

func TestSortFindingsOrdersBySourceThenRefIDForIdenticalCVEAndPackage(t *testing.T) {
	// Same CVE and same package.CategoryName()/Version (a scenario that
	// could arise once both GLSA and OSV.dev are matched together), but two
	// different sources: order must still be fully deterministic.
	pkg := sbom.Package{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"}
	findings := []Finding{
		{CVE: "CVE-2026-1", Source: SourceOSV, RefID: "GHSA-b", Package: pkg},
		{CVE: "CVE-2026-1", Source: SourceGLSA, RefID: "202604-02", Package: pkg},
		{CVE: "CVE-2026-1", Source: SourceGLSA, RefID: "202604-01", Package: pkg},
	}

	sortFindings(findings)

	want := []struct{ source, refID string }{
		{SourceGLSA, "202604-01"},
		{SourceGLSA, "202604-02"},
		{SourceOSV, "GHSA-b"},
	}
	for i, w := range want {
		if findings[i].Source != w.source || findings[i].RefID != w.refID {
			t.Errorf("findings[%d] = {Source: %q, RefID: %q}, want {%q, %q}", i, findings[i].Source, findings[i].RefID, w.source, w.refID)
		}
	}
}

func TestApplyCurlAdvisories(t *testing.T) {
	curl := func(version string) sbom.Package {
		return sbom.Package{Category: "net-misc", Name: "curl", Version: version}
	}
	glsaFinding := func(cve string, pkg sbom.Package) Finding {
		return Finding{CVE: cve, Source: SourceGLSA, RefID: "202611-07", Package: pkg, Status: StatusAffected}
	}
	findings := []Finding{
		glsaFinding("CVE-2024-11053", curl("8.21.0-r1")), // fixed upstream in 8.11.1
		glsaFinding("CVE-2026-13608", curl("8.21.0-r1")), // 8.21.0 is listed upstream
		glsaFinding("CVE-2026-0001", curl("8.21.0-r1")),  // no upstream record
		glsaFinding("CVE-2024-11053", sbom.Package{Category: "net-misc", Name: "wget", Version: "1.0"}),
		{CVE: "CVE-2024-11053", Source: SourceOSV, RefID: "X", Package: curl("8.21.0"), Status: StatusAffected},
	}

	if got, want := strings.Join(CurlAdvisoryIDs(findings), ","), "CURL-CVE-2024-11053,CURL-CVE-2026-0001,CURL-CVE-2026-13608"; got != want {
		t.Errorf("CurlAdvisoryIDs = %s, want %s", got, want)
	}

	advisories := map[string]osv.Vulnerability{
		"CURL-CVE-2024-11053": {ID: "CURL-CVE-2024-11053", AffectedVersions: []string{"8.11.0", "8.10.1"}},
		"CURL-CVE-2026-13608": {ID: "CURL-CVE-2026-13608", AffectedVersions: []string{"8.22.0", "8.21.0"}},
	}
	got := ApplyCurlAdvisories(findings, advisories)

	want := []Status{StatusNotAffected, StatusAffected, StatusAffected, StatusAffected, StatusAffected}
	for i, f := range got {
		if f.Status != want[i] {
			t.Errorf("finding %d (%s %s): status %s, want %s", i, f.CVE, f.Package.CategoryName(), f.Status, want[i])
		}
	}
	if !strings.Contains(got[0].Note, "CURL-CVE-2024-11053") {
		t.Errorf("note %q does not name the curl advisory", got[0].Note)
	}
	if findings[0].Status != StatusAffected {
		t.Error("input findings were modified")
	}
}

func TestApplyCurlAdvisoriesKeepsUnmappableVersions(t *testing.T) {
	advisories := map[string]osv.Vulnerability{
		"CURL-CVE-2026-13608": {ID: "CURL-CVE-2026-13608", AffectedVersions: []string{"8.21.0"}},
	}
	for _, version := range []string{"8.21.0_p1-r1", "8.21.0_rc1", "8.21.0_pre20260101", "9999"} {
		f := Finding{CVE: "CVE-2026-13608", Source: SourceGLSA, RefID: "202611-07", Status: StatusAffected,
			Package: sbom.Package{Category: "net-misc", Name: "curl", Version: version}}
		if got := ApplyCurlAdvisories([]Finding{f}, advisories)[0].Status; got != StatusAffected {
			t.Errorf("version %s: status %s, want %s", version, got, StatusAffected)
		}
	}
}

func TestRunOSVPropagatesCVEsAcrossAliasGroups(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "golang", Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
		{Category: "golang", Name: "example.com/mod", Version: "v1.1.0", PURL: "pkg:golang/example.com/mod@v1.1.0"},
	}
	client := newOSVTestClient(t, map[string][]string{
		"pkg:golang/example.com/mod@v1.0.0": {"GHSA-aaaa"},
		"pkg:golang/example.com/mod@v1.1.0": {"GO-2026-1"},
	}, map[string][]string{
		"GHSA-aaaa": {"GO-2026-1"},
		"GO-2026-1": {"GHSA-aaaa", "CVE-2026-1"},
	})

	findings, err := RunOSV(context.Background(), pkgs, client)
	if err != nil {
		t.Fatalf("RunOSV returned error: %v", err)
	}
	var got []string
	for _, f := range findings {
		got = append(got, f.Package.Version+" "+f.CVE+" "+f.RefID)
	}
	slices.Sort(got)
	want := []string{"v1.0.0 CVE-2026-1 GHSA-aaaa", "v1.1.0 CVE-2026-1 GO-2026-1"}
	if !slices.Equal(got, want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
}

// Advisory entries may share one backing array. Evaluating one entry must
// not overwrite another entry's ranges.
func TestEvaluateDoesNotModifyAdvisoryRanges(t *testing.T) {
	shared := make([]glsa.VersionRange, 2, 3)
	shared[0] = glsa.VersionRange{Op: "lt", Version: "2.0"}
	shared[1] = glsa.VersionRange{Op: "lt", Version: "5.0"}
	other := shared[1]
	affected := glsa.AffectedPackage{
		Vulnerable: shared[:1],
		Unaffected: []glsa.VersionRange{{Op: "ge", Version: "2.0"}},
	}

	evaluate("1.0", affected)

	if shared[1] != other {
		t.Errorf("evaluate overwrote a shared range: got %+v, want %+v", shared[1], other)
	}
}
