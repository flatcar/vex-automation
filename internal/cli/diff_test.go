package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flatcar/vex-automation/internal/diff"
)

// sbomJSON builds a minimal SPDX SBOM named after the given release
// segment (e.g. "stable-4593.2.4-a1") with the given purls.
func sbomJSON(release string, purls ...string) string {
	pkgs := make([]string, len(purls))
	for i, p := range purls {
		_, version, _ := strings.Cut(p[strings.LastIndex(p, "/"):], "@")
		version, _, _ = strings.Cut(version, "?")
		pkgs[i] = fmt.Sprintf(`{"name": "p%d", "versionInfo": %q, "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": %q}]}`, i, version, p)
	}
	return fmt.Sprintf(`{"spdxVersion": "SPDX-2.3", "name": "/build/images/amd64-usr/%s/rootfs", "packages": [%s]}`,
		release, strings.Join(pkgs, ",\n"))
}

// fakeOSV is an OSV.dev fake that reports vulnerabilities only for exact
// Go module versions, and records the queries it receives.
type fakeOSV struct {
	mu      sync.Mutex
	batches int
	queries []string
}

// newFakeOSVServer serves vulns, keyed by "module@version", each value
// being an OSV ID and its (possibly empty) CVE alias. It also serves curl's
// own advisories: curl maps "CURL-<CVE>" record IDs to their affected
// versions, and any other "CURL-" ID is answered with 404 like OSV.dev does
// for unknown IDs.
func newVersionedFakeOSVServer(t *testing.T, vulns map[string][2]string, curl map[string][]string) (*httptest.Server, *fakeOSV) {
	t.Helper()
	fake := &fakeOSV{}
	aliases := map[string]string{}
	for _, v := range vulns {
		aliases[v[0]] = v[1]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		type vuln struct {
			ID string `json:"id"`
		}
		type result struct {
			Vulns []vuln `json:"vulns"`
		}
		results := make([]result, len(req.Queries))
		fake.mu.Lock()
		fake.batches++
		for i, q := range req.Queries {
			k := q.Package.Name + "@" + q.Version
			fake.queries = append(fake.queries, k)
			if v, ok := vulns[k]; ok {
				results[i].Vulns = []vuln{{ID: v[0]}}
			}
		}
		fake.mu.Unlock()
		_ = json.NewEncoder(w).Encode(struct {
			Results []result `json:"results"`
		}{results})
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if versions, ok := curl[id]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": id, "aliases": []string{strings.TrimPrefix(id, "CURL-")},
				"affected": []map[string]any{{"versions": versions}},
			})
			return
		}
		if strings.HasPrefix(id, "CURL-") {
			http.Error(w, "Bug not found.", http.StatusNotFound)
			return
		}
		var al []string
		if a := aliases[id]; a != "" {
			al = []string{a}
		}
		_ = json.NewEncoder(w).Encode(struct {
			ID      string   `json:"id"`
			Aliases []string `json:"aliases"`
		}{id, al})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, fake
}

type diffFixture struct {
	oldSBOM, newSBOM, glsaDir string
}

func writeDiffFixture(t *testing.T) diffFixture {
	t.Helper()
	dir := t.TempDir()
	f := diffFixture{
		oldSBOM: filepath.Join(dir, "old.json"),
		newSBOM: filepath.Join(dir, "new.json"),
		glsaDir: filepath.Join(dir, "glsa"),
	}
	if err := os.Mkdir(f.glsaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(f.glsaDir, "glsa-202604-03.xml"), testGLSA)
	writeTestFile(t, f.oldSBOM, sbomJSON("stable-4593.2.4-a1",
		"pkg:ebuild/sys-fs/fuse@3.17.0",
		"pkg:golang/example.com/mod@v1.0.0",
		"pkg:golang/example.com/mod@v1.0.0?type=module",
		"pkg:golang/example.com/gone@v1.0.0",
	))
	writeTestFile(t, f.newSBOM, sbomJSON("alpha-4865.0.0-a1",
		"pkg:ebuild/sys-fs/fuse@3.18.1",
		"pkg:golang/example.com/mod@v1.1.0",
		"pkg:golang/example.com/new@v0.1.0",
		"pkg:generic/linux-kernel@6.12.95-flatcar",
	))
	return f
}

var diffFixtureVulns = map[string][2]string{
	"example.com/mod@v1.0.0":  {"GHSA-aaaa-bbbb-cccc", "CVE-2026-1111"},
	"example.com/gone@v1.0.0": {"GO-2026-0001", ""},
	"example.com/new@v0.1.0":  {"GO-2026-0002", ""},
}

func execDiff(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(append([]string{"diff"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

func TestDiffCmdJSON(t *testing.T) {
	f := writeDiffFixture(t)
	srv, fake := newVersionedFakeOSVServer(t, diffFixtureVulns, nil)

	out, err := execDiff(t, "--old-sbom", f.oldSBOM, "--new-sbom", f.newSBOM, "--glsa-dir", f.glsaDir, "--osv-base-url", srv.URL)
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}

	var res diff.Result
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	var got []string
	for _, e := range res.Entries {
		got = append(got, fmt.Sprintf("%s %s %s %s->%s", e.Bucket, e.Package, e.ID, e.Old.State, e.New.State))
	}
	want := []string{
		"fixed example.com/mod CVE-2026-1111 affected->clean",
		"fixed sys-fs/fuse CVE-2026-33150 affected->fixed",
		"removed example.com/gone GO-2026-0001 affected->absent",
		"introduced example.com/new GO-2026-0002 absent->affected",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("entries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if res.Old.ProductID != "pkg:generic/flatcar-container-linux@4593.2.4-a1?channel=stable" ||
		res.New.ProductID != "pkg:generic/flatcar-container-linux@4865.0.0-a1?channel=alpha" {
		t.Errorf("product IDs = %q, %q", res.Old.ProductID, res.New.ProductID)
	}
	if len(res.NotChecked.New) != 1 || res.NotChecked.New[0].Name == "" || res.NotChecked.OSVDisabled {
		t.Errorf("not_checked = %+v", res.NotChecked)
	}
	if !strings.HasSuffix(out, "}\n") || !strings.Contains(out, "\n  \"schema_version\": 1") {
		t.Errorf("output is not indented JSON with a trailing newline:\n%s", out)
	}

	// Both sides are matched in one OSV.dev pass over the deduplicated union.
	if fake.batches != 1 {
		t.Errorf("querybatch requests = %d, want 1", fake.batches)
	}
	if len(fake.queries) != 4 {
		t.Errorf("queries = %v, want the 4 distinct module versions", fake.queries)
	}

	again, err := execDiff(t, "--old-sbom", f.oldSBOM, "--new-sbom", f.newSBOM, "--glsa-dir", f.glsaDir, "--osv-base-url", srv.URL)
	if err != nil || again != out {
		t.Fatalf("second run differs (err %v)", err)
	}
}

func TestDiffCmdChangelog(t *testing.T) {
	f := writeDiffFixture(t)
	srv, _ := newVersionedFakeOSVServer(t, diffFixtureVulns, nil)
	outPath := filepath.Join(t.TempDir(), "out", "security.md")

	if _, err := execDiff(t, "--old-sbom", f.oldSBOM, "--new-sbom", f.newSBOM, "--glsa-dir", f.glsaDir,
		"--osv-base-url", srv.URL, "--format", "changelog", "-o", outPath); err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "- example.com/mod ([CVE-2026-1111](https://www.cve.org/CVERecord?id=CVE-2026-1111))\n" +
		"- fuse ([CVE-2026-33150](https://www.cve.org/CVERecord?id=CVE-2026-33150))\n"
	if string(got) != want {
		t.Fatalf("changelog =\n%s\nwant\n%s", got, want)
	}
}

func TestDiffCmdOSVDisabled(t *testing.T) {
	f := writeDiffFixture(t)

	out, err := execDiff(t, "--old-sbom", f.oldSBOM, "--new-sbom", f.newSBOM, "--glsa-dir", f.glsaDir, "--osv=false")
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	var res diff.Result
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if !res.NotChecked.OSVDisabled || !strings.Contains(res.Tooling, "OSV.dev disabled") {
		t.Errorf("OSV.dev being disabled is not recorded: %+v / %q", res.NotChecked, res.Tooling)
	}
	if len(res.Entries) != 1 || res.Entries[0].Package != "sys-fs/fuse" {
		t.Errorf("entries = %+v, want only the GLSA fix", res.Entries)
	}
}

func TestDiffCmdErrors(t *testing.T) {
	f := writeDiffFixture(t)
	base := []string{"--old-sbom", f.oldSBOM, "--new-sbom", f.newSBOM, "--glsa-dir", f.glsaDir, "--osv=false"}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing new SBOM", []string{"--old-sbom", f.oldSBOM, "--glsa-dir", f.glsaDir}, "new-sbom"},
		{"unknown format", append(base, "--format", "yaml"), "--format"},
		{"negative OSV timeout", []string{"--old-sbom", f.oldSBOM, "--new-sbom", f.newSBOM, "--glsa-dir", f.glsaDir, "--osv-timeout", "-1s"}, "--osv-timeout"},
		{"unreadable SBOM", []string{"--old-sbom", "/nonexistent", "--new-sbom", f.newSBOM, "--glsa-dir", f.glsaDir, "--osv=false"}, "/nonexistent"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execDiff(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

const curlGLSA = `<?xml version="1.0" encoding="UTF-8"?>
<glsa id="202611-07">
    <title>curl: Multiple Vulnerabilities</title>
    <affected>
        <package name="net-misc/curl" arch="*">
            <unaffected range="ge">8.23.0</unaffected>
            <vulnerable range="lt">8.23.0</vulnerable>
        </package>
    </affected>
    <references>
        <uri link="https://nvd.nist.gov/vuln/detail/CVE-2024-11053">CVE-2024-11053</uri>
        <uri link="https://nvd.nist.gov/vuln/detail/CVE-2026-13608">CVE-2026-13608</uri>
        <uri link="https://nvd.nist.gov/vuln/detail/CVE-2026-0001">CVE-2026-0001</uri>
    </references>
</glsa>`

// TestDiffCmdCurlUpstreamVersions covers GLSAs that bundle years of curl
// CVEs under one version range: curl's own advisories decide whether the
// older release was really affected.
func TestDiffCmdCurlUpstreamVersions(t *testing.T) {
	dir := t.TempDir()
	glsaDir := filepath.Join(dir, "glsa")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(glsaDir, "glsa-202611-07.xml"), curlGLSA)
	oldSBOM, newSBOM := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
	writeTestFile(t, oldSBOM, sbomJSON("alpha-4820.0.1-a1", "pkg:ebuild/net-misc/curl@8.21.0-r1"))
	writeTestFile(t, newSBOM, sbomJSON("alpha-4865.0.0-a1", "pkg:ebuild/net-misc/curl@8.23.0"))
	srv, _ := newVersionedFakeOSVServer(t, nil, map[string][]string{
		"CURL-CVE-2024-11053": {"8.11.0", "8.10.1"},
		"CURL-CVE-2026-13608": {"8.22.0", "8.21.0"},
	})

	run := func(args ...string) []string {
		t.Helper()
		out, err := execDiff(t, append([]string{"--old-sbom", oldSBOM, "--new-sbom", newSBOM, "--glsa-dir", glsaDir}, args...)...)
		if err != nil {
			t.Fatalf("diff failed: %v", err)
		}
		var res diff.Result
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatal(err)
		}
		var fixed []string
		for _, e := range res.Entries {
			if e.Bucket == diff.BucketFixed {
				fixed = append(fixed, e.ID)
			}
		}
		return fixed
	}

	// CVE-2024-11053 was fixed upstream long before 8.21.0, so the old
	// release was not affected; CVE-2026-0001 has no curl advisory, so the
	// GLSA stands.
	if got, want := strings.Join(run("--osv-base-url", srv.URL), ","), "CVE-2026-0001,CVE-2026-13608"; got != want {
		t.Errorf("fixed = %s, want %s", got, want)
	}
	if got, want := strings.Join(run("--osv=false"), ","), "CVE-2024-11053,CVE-2026-0001,CVE-2026-13608"; got != want {
		t.Errorf("with --osv=false fixed = %s, want %s", got, want)
	}
}

// --osv-timeout bounds all OSV.dev work of one diff run: the curl advisory
// recheck and the golang/cargo matching share one deadline.
func TestDiffCmdOSVTimeoutCoversAllOSVWork(t *testing.T) {
	dir := t.TempDir()
	glsaDir := filepath.Join(dir, "glsa")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(glsaDir, "glsa-202611-07.xml"), curlGLSA)
	oldSBOM, newSBOM := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
	writeTestFile(t, oldSBOM, sbomJSON("alpha-4820.0.1-a1", "pkg:ebuild/net-misc/curl@8.21.0-r1", "pkg:golang/example.com/mod@v1.0.0"))
	writeTestFile(t, newSBOM, sbomJSON("alpha-4865.0.0-a1", "pkg:ebuild/net-misc/curl@8.23.0", "pkg:golang/example.com/mod@v1.1.0"))
	backend, _ := newVersionedFakeOSVServer(t, nil, map[string][]string{"CURL-CVE-2024-11053": {"8.11.0"}})

	// Each stage takes about 300ms: the curl recheck is one round of
	// parallel GETs, the matching one querybatch.
	const stage = 300 * time.Millisecond
	target, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(stage):
		case <-r.Context().Done():
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(slow.Close)

	args := []string{"--old-sbom", oldSBOM, "--new-sbom", newSBOM, "--glsa-dir", glsaDir, "--osv-base-url", slow.URL}
	if _, err := execDiff(t, append(args, "--osv-timeout", "5s")...); err != nil {
		t.Fatalf("diff with a generous timeout failed: %v", err)
	}
	if _, err := execDiff(t, append(args, "--osv-timeout", "450ms")...); err == nil {
		t.Fatal("diff succeeded although its OSV.dev work took about 600ms with --osv-timeout=450ms")
	}
}
