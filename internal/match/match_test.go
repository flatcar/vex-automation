package match

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	findings := Run(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per CVE): %+v", len(findings), findings)
	}
	for _, f := range findings {
		if !f.Affected {
			t.Errorf("finding %+v: want Affected=true for version below the unaffected range", f)
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

	findings := Run(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.Affected {
			t.Errorf("finding %+v: want Affected=false for version at the unaffected boundary", f)
		}
	}
}

func TestRunNoMatchingPackage(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-apps", Name: "systemd", Version: "255.4-r2", PURL: "pkg:ebuild/sys-apps/systemd@255.4-r2"},
	}

	findings := Run(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")
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

	findings := Run(pkgs, []glsa.GLSA{g}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 when GLSA arch doesn't match", len(findings))
	}
}

func TestRunSkipsUnparseableVersion(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "not-a-version!!", PURL: "pkg:ebuild/sys-fs/fuse@bogus"},
	}

	findings := Run(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 when the installed version can't be parsed", len(findings))
	}
}

func TestRunGLSAWithNoCVEsIsSkipped(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
	}
	g := fuseGLSA()
	g.CVEs = nil

	findings := Run(pkgs, []glsa.GLSA{g}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 for a GLSA with no CVE references", len(findings))
	}
}

// newOSVTestClient starts an httptest.Server that answers querybatch/vulns
// requests from a fixed map of query-purl -> vulnerability IDs, plus vuln ID
// -> alias, and returns an *osv.Client pointed at it.
func newOSVTestClient(t *testing.T, vulnsByPurl map[string][]string, aliasesByID map[string][]string) *osv.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct {
					PURL string `json:"purl"`
				} `json:"package"`
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
			for _, id := range vulnsByPurl[q.Package.PURL] {
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
	if !f.Affected {
		t.Error("want Affected=true for an OSV.dev finding")
	}
	if f.Package.PURL != "pkg:golang/example.com/mod@v1.0.0" {
		t.Errorf("Package.PURL = %q, want the original SBOM purl preserved", f.Package.PURL)
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
	findings, err := RunOSV(context.Background(), nil, osv.NewClient())
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
