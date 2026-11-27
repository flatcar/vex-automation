package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/flatcar/vex-automation/internal/sbom"
	"github.com/flatcar/vex-automation/internal/vuln"
)

// newOSVTestClient starts an httptest.Server that answers querybatch/vulns
// requests from a fixed map of "pkg:<type>/<name>@<version>" ->
// vulnerability IDs, plus vuln ID -> alias, and returns an *Client
// pointed at it. Like OSV.dev, it lowercases purl queries, while
// name/ecosystem queries are matched case-sensitively.
func newOSVTestClient(t *testing.T, vulnsByPurl map[string][]string, aliasesByID map[string][]string) *Client {
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
	return &Client{BaseURL: srv.URL}
}

func TestMatchBuildsFindingsFromResults(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Golang, Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
	}
	client := newOSVTestClient(t,
		map[string][]string{"pkg:golang/example.com/mod@v1.0.0": {"GHSA-aaaa"}},
		map[string][]string{"GHSA-aaaa": {"CVE-2026-9999"}},
	)

	findings, err := Match(context.Background(), pkgs, client)
	if err != nil {
		t.Fatalf("Match returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.CVE != "CVE-2026-9999" {
		t.Errorf("CVE = %q, want CVE-2026-9999", f.CVE)
	}
	if f.Source != vuln.SourceOSV {
		t.Errorf("Source = %q, want %q", f.Source, vuln.SourceOSV)
	}
	if f.RefID != "GHSA-aaaa" {
		t.Errorf("RefID = %q, want GHSA-aaaa", f.RefID)
	}
	if f.Status != vuln.StatusAffected {
		t.Errorf("Status = %q, want affected for an OSV.dev finding", f.Status)
	}
	if f.Package.PURL != "pkg:golang/example.com/mod@v1.0.0" {
		t.Errorf("Package.PURL = %q, want the original SBOM purl preserved", f.Package.PURL)
	}
}

// A single OSV.dev record can alias several CVEs; each must become a
// finding, not just the first.
func TestMatchReportsEveryCVEAlias(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Golang, Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
	}
	client := newOSVTestClient(t,
		map[string][]string{"pkg:golang/example.com/mod@v1.0.0": {"GO-2026-1"}},
		map[string][]string{"GO-2026-1": {"CVE-2026-2", "GHSA-x", "CVE-2026-1"}},
	)

	findings, err := Match(context.Background(), pkgs, client)
	if err != nil {
		t.Fatalf("Match returned error: %v", err)
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
func TestMatchReportsAliasedRecordsWithoutCVEOnce(t *testing.T) {
	// The alias may be recorded on either side only.
	for name, aliases := range map[string]map[string][]string{
		"GO lists GHSA": {"GO-2026-1": {"GHSA-aaaa"}},
		"GHSA lists GO": {"GHSA-aaaa": {"GO-2026-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			pkgs := []sbom.Package{
				{Ecosystem: sbom.Golang, Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
			}
			client := newOSVTestClient(t,
				map[string][]string{"pkg:golang/example.com/mod@v1.0.0": {"GO-2026-1", "GHSA-aaaa", "GO-2026-2"}},
				aliases,
			)

			findings, err := Match(context.Background(), pkgs, client)
			if err != nil {
				t.Fatalf("Match returned error: %v", err)
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
func TestMatchCanonicalizesAliasedRecordsAcrossPackages(t *testing.T) {
	for name, aliases := range map[string]map[string][]string{
		"GO lists GHSA": {"GO-2026-1": {"GHSA-aaaa"}},
		"GHSA lists GO": {"GHSA-aaaa": {"GO-2026-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			pkgs := []sbom.Package{
				{Ecosystem: sbom.Golang, Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
				{Ecosystem: sbom.Golang, Name: "example.com/mod", Version: "v1.1.0", PURL: "pkg:golang/example.com/mod@v1.1.0"},
			}
			client := newOSVTestClient(t, map[string][]string{
				"pkg:golang/example.com/mod@v1.0.0": {"GO-2026-1", "GHSA-aaaa"},
				"pkg:golang/example.com/mod@v1.1.0": {"GO-2026-1"},
			}, aliases)

			findings, err := Match(context.Background(), pkgs, client)
			if err != nil {
				t.Fatalf("Match returned error: %v", err)
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
func TestMatchQueriesNormalizedModuleAndVersion(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Golang, Name: "github.com/golang-jwt/jwt/v4", Version: "v4.5.1", PURL: "pkg:golang/github.com/golang-jwt/jwt@v4.5.1#v4"},
		{Ecosystem: sbom.Golang, Name: "stdlib", Version: "1.25.3", PURL: "pkg:golang/stdlib@1.25.3"},
		{Ecosystem: sbom.Golang, Name: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Version: "v1.5.0", PURL: "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.5.0"},
		{Ecosystem: sbom.Cargo, Name: "smallvec", Version: "1.6.0", PURL: "pkg:cargo/smallvec@1.6.0"},
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

	findings, err := Match(context.Background(), pkgs, client)
	if err != nil {
		t.Fatalf("Match returned error: %v", err)
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

func TestMatchNoVulnerabilities(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Golang, Name: "example.com/safe", Version: "v1.0.0", PURL: "pkg:golang/example.com/safe@v1.0.0"},
	}
	client := newOSVTestClient(t, nil, nil)

	findings, err := Match(context.Background(), pkgs, client)
	if err != nil {
		t.Fatalf("Match returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestMatchEmptyPackages(t *testing.T) {
	findings, err := Match(context.Background(), nil, &Client{})
	if err != nil {
		t.Fatalf("Match returned error: %v", err)
	}
	if findings != nil {
		t.Errorf("got %+v, want nil", findings)
	}
}

func TestApplyCurlAdvisories(t *testing.T) {
	curl := func(version string) sbom.Package {
		return sbom.Package{Ecosystem: sbom.Ebuild, Category: "net-misc", Name: "curl", Version: version}
	}
	glsaFinding := func(cve string, pkg sbom.Package) vuln.Finding {
		return vuln.Finding{CVE: cve, Source: vuln.SourceGLSA, RefID: "202611-07", Package: pkg, Status: vuln.StatusAffected}
	}
	findings := []vuln.Finding{
		glsaFinding("CVE-2024-11053", curl("8.21.0-r1")), // fixed upstream in 8.11.1
		glsaFinding("CVE-2026-13608", curl("8.21.0-r1")), // 8.21.0 is listed upstream
		glsaFinding("CVE-2026-0001", curl("8.21.0-r1")),  // no upstream record
		glsaFinding("CVE-2024-11053", sbom.Package{Ecosystem: sbom.Ebuild, Category: "net-misc", Name: "wget", Version: "1.0"}),
		{CVE: "CVE-2024-11053", Source: vuln.SourceOSV, RefID: "X", Package: curl("8.21.0"), Status: vuln.StatusAffected},
	}

	if got, want := strings.Join(CurlAdvisoryIDs(findings), ","), "CURL-CVE-2024-11053,CURL-CVE-2026-0001,CURL-CVE-2026-13608"; got != want {
		t.Errorf("CurlAdvisoryIDs = %s, want %s", got, want)
	}

	advisories := map[string]Vulnerability{
		"CURL-CVE-2024-11053": {ID: "CURL-CVE-2024-11053", AffectedVersions: []string{"8.11.0", "8.10.1"}},
		"CURL-CVE-2026-13608": {ID: "CURL-CVE-2026-13608", AffectedVersions: []string{"8.22.0", "8.21.0"}},
	}
	got := ApplyCurlAdvisories(findings, advisories)

	want := []vuln.Status{vuln.StatusNotAffected, vuln.StatusAffected, vuln.StatusAffected, vuln.StatusAffected, vuln.StatusAffected}
	for i, f := range got {
		if f.Status != want[i] {
			t.Errorf("finding %d (%s %s): status %s, want %s", i, f.CVE, f.Package.FullName(), f.Status, want[i])
		}
	}
	if !strings.Contains(got[0].Note, "CURL-CVE-2024-11053") {
		t.Errorf("note %q does not name the curl advisory", got[0].Note)
	}
	if findings[0].Status != vuln.StatusAffected {
		t.Error("input findings were modified")
	}
}

func TestApplyCurlAdvisoriesKeepsUnmappableVersions(t *testing.T) {
	advisories := map[string]Vulnerability{
		"CURL-CVE-2026-13608": {ID: "CURL-CVE-2026-13608", AffectedVersions: []string{"8.21.0"}},
	}
	for _, version := range []string{"8.21.0_p1-r1", "8.21.0_rc1", "8.21.0_pre20260101", "9999"} {
		f := vuln.Finding{CVE: "CVE-2026-13608", Source: vuln.SourceGLSA, RefID: "202611-07", Status: vuln.StatusAffected,
			Package: sbom.Package{Ecosystem: sbom.Ebuild, Category: "net-misc", Name: "curl", Version: version}}
		if got := ApplyCurlAdvisories([]vuln.Finding{f}, advisories)[0].Status; got != vuln.StatusAffected {
			t.Errorf("version %s: status %s, want %s", version, got, vuln.StatusAffected)
		}
	}
}

func TestMatchPropagatesCVEsAcrossAliasGroups(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Golang, Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
		{Ecosystem: sbom.Golang, Name: "example.com/mod", Version: "v1.1.0", PURL: "pkg:golang/example.com/mod@v1.1.0"},
	}
	client := newOSVTestClient(t, map[string][]string{
		"pkg:golang/example.com/mod@v1.0.0": {"GHSA-aaaa"},
		"pkg:golang/example.com/mod@v1.1.0": {"GO-2026-1"},
	}, map[string][]string{
		"GHSA-aaaa": {"GO-2026-1"},
		"GO-2026-1": {"GHSA-aaaa", "CVE-2026-1"},
	})

	findings, err := Match(context.Background(), pkgs, client)
	if err != nil {
		t.Fatalf("Match returned error: %v", err)
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
