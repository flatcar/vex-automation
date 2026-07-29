package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flatcar/vex-automation/internal/sbom"
)

const testSBOM = `{
  "name": "/home/sdk/trunk/src/build/images/amd64-usr/stable-4593.2.4-a1/rootfs-with-sysext-pkgs",
  "packages": [
    {
      "name": "fuse",
      "versionInfo": "3.17.0",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:ebuild/sys-fs/fuse@3.17.0"}
      ]
    }
  ]
}`

// testSBOMWithGoModule additionally describes a golang purl, for exercising
// --osv matching.
const testSBOMWithGoModule = `{
  "name": "/home/sdk/trunk/src/build/images/amd64-usr/stable-4593.2.4-a1/rootfs-with-sysext-pkgs",
  "packages": [
    {
      "name": "fuse",
      "versionInfo": "3.17.0",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:ebuild/sys-fs/fuse@3.17.0"}
      ]
    },
    {
      "name": "vulnerable-module",
      "versionInfo": "v1.0.0",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/example.com/vulnerable-module@v1.0.0"}
      ]
    }
  ]
}`

const testGLSA = `<?xml version="1.0" encoding="UTF-8"?>
<glsa id="202604-03">
    <title>FUSE: Multiple Vulnerabilities</title>
    <affected>
        <package name="sys-fs/fuse" arch="*">
            <unaffected range="ge">3.18.1</unaffected>
            <vulnerable range="lt">3.18.1</vulnerable>
        </package>
    </affected>
    <references>
        <uri link="https://nvd.nist.gov/vuln/detail/CVE-2026-33150">CVE-2026-33150</uri>
    </references>
</glsa>`

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// newFakeOSVServer starts an httptest.Server that reports oneVulnID for
// every querybatch query, aliased to oneVulnCVE.
func newFakeOSVServer(t *testing.T, oneVulnID, oneVulnCVE string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct{} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		type vuln struct {
			ID string `json:"id"`
		}
		type result struct {
			Vulns []vuln `json:"vulns"`
		}
		results := make([]result, len(req.Queries))
		for i := range results {
			results[i] = result{Vulns: []vuln{{ID: oneVulnID}}}
		}
		resp := struct {
			Results []result `json:"results"`
		}{Results: results}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/vulns/"+oneVulnID, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(struct {
			ID      string   `json:"id"`
			Aliases []string `json:"aliases"`
		}{ID: oneVulnID, Aliases: []string{oneVulnCVE}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestGenerateCmdWritesVEXToStdout(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	glsaDir := filepath.Join(dir, "glsa")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestFile(t, sbomPath, testSBOM)
	writeTestFile(t, filepath.Join(glsaDir, "glsa-202604-03.xml"), testGLSA)

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"generate", "--sbom", sbomPath, "--glsa-dir", glsaDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v\noutput: %s", err, out.String())
	}

	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out.String())
	}

	statements, ok := doc["statements"].([]any)
	if !ok || len(statements) != 1 {
		t.Fatalf("expected exactly 1 statement, got: %v", doc["statements"])
	}
	stmt := statements[0].(map[string]any)
	if stmt["status"] != "affected" {
		t.Errorf("status = %v, want %q", stmt["status"], "affected")
	}

	products, _ := stmt["products"].([]any)
	if len(products) != 1 {
		t.Fatalf("expected 1 product, got %v", stmt["products"])
	}
	product := products[0].(map[string]any)
	wantProductID := "pkg:generic/flatcar-container-linux@4593.2.4-a1?channel=stable"
	if product["@id"] != wantProductID {
		t.Errorf("product @id = %v, want %q (derived from SBOM document name)", product["@id"], wantProductID)
	}
}

func TestGenerateCmdWritesVEXToFile(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	glsaDir := filepath.Join(dir, "glsa")
	outPath := filepath.Join(dir, "out", "flatcar.vex.json")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestFile(t, sbomPath, testSBOM)
	writeTestFile(t, filepath.Join(glsaDir, "glsa-202604-03.xml"), testGLSA)

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"generate", "--sbom", sbomPath, "--glsa-dir", glsaDir, "-o", outPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v\noutput: %s", err, out.String())
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if !strings.Contains(string(data), "CVE-2026-33150") {
		t.Errorf("output file missing expected CVE: %s", data)
	}
}

func TestGenerateCmdMissingRequiredFlags(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"generate"})

	if err := cmd.Execute(); err == nil {
		t.Error("expected an error when --sbom/--glsa-dir are missing, got nil")
	}
}

func TestGenerateCmdMissingSBOMFile(t *testing.T) {
	dir := t.TempDir()
	glsaDir := filepath.Join(dir, "glsa")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"generate", "--sbom", filepath.Join(dir, "does-not-exist.json"), "--glsa-dir", glsaDir})

	if err := cmd.Execute(); err == nil {
		t.Error("expected an error for a missing SBOM file, got nil")
	}
}

func TestGenerateCmdWithOSVMergesFindings(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	glsaDir := filepath.Join(dir, "glsa")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestFile(t, sbomPath, testSBOMWithGoModule)
	writeTestFile(t, filepath.Join(glsaDir, "glsa-202604-03.xml"), testGLSA)

	srv := newFakeOSVServer(t, "GHSA-osv-test", "CVE-2026-4242")

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"generate",
		"--sbom", sbomPath,
		"--glsa-dir", glsaDir,
		"--osv",
		"--osv-base-url", srv.URL,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v\noutput: %s", err, out.String())
	}

	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out.String())
	}

	statements, _ := doc["statements"].([]any)
	if len(statements) != 2 {
		t.Fatalf("expected 2 statements (one GLSA, one OSV), got %d: %v", len(statements), statements)
	}

	var sawGLSACVE, sawOSVCVE bool
	for _, s := range statements {
		stmt := s.(map[string]any)
		vuln, _ := stmt["vulnerability"].(map[string]any)
		switch vuln["name"] {
		case "CVE-2026-33150":
			sawGLSACVE = true
		case "CVE-2026-4242":
			sawOSVCVE = true
			if stmt["status"] != "affected" {
				t.Errorf("OSV finding status = %v, want affected", stmt["status"])
			}
		}
	}
	if !sawGLSACVE {
		t.Error("expected the GLSA-derived CVE-2026-33150 statement to still be present")
	}
	if !sawOSVCVE {
		t.Error("expected the OSV.dev-derived CVE-2026-4242 statement to be present")
	}
}

func TestGenerateCmdWithoutOSVFlagSkipsOSVMatching(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	glsaDir := filepath.Join(dir, "glsa")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestFile(t, sbomPath, testSBOMWithGoModule)
	writeTestFile(t, filepath.Join(glsaDir, "glsa-202604-03.xml"), testGLSA)

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	// Deliberately no --osv flag and no network access: this must not make
	// any HTTP request, and the golang package present in the SBOM must be
	// silently ignored (same as today's GLSA-only behavior).
	cmd.SetArgs([]string{"generate", "--sbom", sbomPath, "--glsa-dir", glsaDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v\noutput: %s", err, out.String())
	}

	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out.String())
	}
	statements, _ := doc["statements"].([]any)
	if len(statements) != 1 {
		t.Fatalf("expected 1 statement (GLSA only, OSV.dev not queried), got %d: %v", len(statements), statements)
	}
}

// TestGenerateCmdWithOSVRejectsEmptyBaseURL guards against a confusing
// low-level URL-building error surfacing when a user passes --osv along
// with an empty --osv-base-url (e.g. `--osv-base-url ""`); this must be
// caught early with a clear, actionable error message instead.
func TestGenerateCmdWithOSVRejectsEmptyBaseURL(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	glsaDir := filepath.Join(dir, "glsa")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestFile(t, sbomPath, testSBOMWithGoModule)
	writeTestFile(t, filepath.Join(glsaDir, "glsa-202604-03.xml"), testGLSA)

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"generate",
		"--sbom", sbomPath,
		"--glsa-dir", glsaDir,
		"--osv",
		"--osv-base-url", "",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error for an empty --osv-base-url, got nil")
	}
	if !strings.Contains(err.Error(), "osv-base-url") {
		t.Errorf("error = %q, want a message mentioning --osv-base-url", err.Error())
	}
}

// TestGenerateCmdWithOSVRejectsNegativeTimeout guards against a regression
// where a negative --osv-timeout silently disabled the timeout altogether
// (matchOSV only applies context.WithTimeout when opts.osvTimeout > 0),
// letting an OSV.dev query hang indefinitely instead of failing fast or
// erroring on an obviously-invalid flag value.
func TestGenerateCmdWithOSVRejectsNegativeTimeout(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	glsaDir := filepath.Join(dir, "glsa")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestFile(t, sbomPath, testSBOMWithGoModule)
	writeTestFile(t, filepath.Join(glsaDir, "glsa-202604-03.xml"), testGLSA)

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"generate",
		"--sbom", sbomPath,
		"--glsa-dir", glsaDir,
		"--osv",
		"--osv-timeout", "-1s",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error for a negative --osv-timeout, got nil")
	}
	if !strings.Contains(err.Error(), "osv-timeout") {
		t.Errorf("error = %q, want a message mentioning --osv-timeout", err.Error())
	}
}

// TestMatchOSVAppliesTimeoutEvenWithLooserParentDeadline guards against a
// regression where opts.osvTimeout was only applied if cmd's context had no
// deadline at all, making the flag ineffective whenever an outer caller
// (e.g. a future workflow wrapper) set its own longer deadline.
func TestMatchOSVAppliesTimeoutEvenWithLooserParentDeadline(t *testing.T) {
	// Server intentionally responds slower than opts.osvTimeout below.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	root := NewRootCmd()
	// Parent deadline is far looser than opts.osvTimeout, so this only
	// passes if matchOSV's own timeout is what fires.
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	root.SetContext(ctx)

	doc := sbom.Document{
		OSVPackages: []sbom.Package{
			{Category: "golang", Name: "example.com/mod", Version: "v1.0.0", PURL: "pkg:golang/example.com/mod@v1.0.0"},
		},
	}
	opts := generateOptions{
		osvBaseURL: srv.URL,
		osvTimeout: 20 * time.Millisecond,
	}

	start := time.Now()
	_, err := matchOSV(root, doc, opts)
	elapsed := time.Since(start)

	// Assert on the error itself (context.DeadlineExceeded), not just wall
	// clock, since a tight wall-clock bound tied to the 20ms timeout would
	// be flaky under CI scheduling jitter. The elapsed-time check below is
	// only a loose sanity check that we didn't wait out the full 200ms
	// server response, with generous headroom above the 20ms timeout.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("matchOSV error = %v, want it to wrap context.DeadlineExceeded from opts.osvTimeout", err)
	}
	if elapsed >= 200*time.Millisecond {
		t.Errorf("matchOSV took %s, want it to respect the 20ms osvTimeout rather than wait out the 200ms server response", elapsed)
	}
}

func TestDeriveProductID(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{
			name: "/home/sdk/trunk/src/build/images/amd64-usr/stable-4593.2.4-a1/rootfs-with-sysext-pkgs",
			want: "pkg:generic/flatcar-container-linux@4593.2.4-a1?channel=stable",
		},
		{
			name: "/home/sdk/trunk/src/build/images/amd64-usr/beta-4600.0.0/rootfs-with-sysext-pkgs",
			want: "pkg:generic/flatcar-container-linux@4600.0.0?channel=beta",
		},
		{
			name: "unrecognized-name",
			want: "pkg:generic/flatcar-container-linux",
		},
	}

	for _, tc := range cases {
		if got := deriveProductID(tc.name); got != tc.want {
			t.Errorf("deriveProductID(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}
