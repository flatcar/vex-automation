package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/flatcar/vex-automation/internal/diff"
)

// releasesManifest describes real Flatcar release pairs whose hand-written
// "Security fixes" release notes serve as ground truth for `diff`. Kernel,
// podman and incus CVEs are left out, as another pipeline handles them.
type releasesManifest struct {
	GLSA struct {
		Repo   string `json:"repo"`
		Commit string `json:"commit"`
	} `json:"glsa"`
	SBOMs map[string]struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
	} `json:"sboms"`
	Pairs []struct {
		Name        string   `json:"name"`
		Old         string   `json:"old"`
		New         string   `json:"new"`
		ExpectFixed []string `json:"expect_fixed"`
		KnownMisses []struct {
			Reason string   `json:"reason"`
			IDs    []string `json:"ids"`
		} `json:"known_misses"`
	} `json:"pairs"`
}

func loadReleasesManifest(t *testing.T) releasesManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "releases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m releasesManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestReleasesManifestConsistent(t *testing.T) {
	m := loadReleasesManifest(t)
	for _, p := range m.Pairs {
		if _, ok := m.SBOMs[p.Old]; !ok {
			t.Errorf("%s: unknown SBOM %q", p.Name, p.Old)
		}
		if _, ok := m.SBOMs[p.New]; !ok {
			t.Errorf("%s: unknown SBOM %q", p.Name, p.New)
		}
		seen := map[string]bool{}
		for _, id := range p.ExpectFixed {
			seen[id] = true
		}
		for _, km := range p.KnownMisses {
			if km.Reason == "" {
				t.Errorf("%s: known miss group without a reason", p.Name)
			}
			for _, id := range km.IDs {
				if seen[id] {
					t.Errorf("%s: %s listed twice", p.Name, id)
				}
				seen[id] = true
			}
		}
	}
}

// TestDiffRealReleases runs `diff` on real release SBOMs against a pinned
// GLSA checkout and live OSV.dev, and checks that every CVE the release
// notes list as fixed (and that the current data sources can reach) is
// reported as fixed. The data is downloaded once into .local/test-cache
// (override with FLATCAR_VEX_TEST_CACHE); use -short to skip.
func TestDiffRealReleases(t *testing.T) {
	if testing.Short() {
		t.Skip("downloads release SBOMs and queries OSV.dev")
	}
	m := loadReleasesManifest(t)
	cache := testCacheDir(t)

	glsaDir := filepath.Join(cache, "glsa")
	ensureGLSACheckout(t, glsaDir, m.GLSA.Repo, m.GLSA.Commit)

	paths := map[string]string{}
	for name, s := range m.SBOMs {
		p := filepath.Join(cache, "sbom-"+name+".json")
		ensureDownload(t, p, s.URL, s.SHA256)
		paths[name] = p
	}

	for _, p := range m.Pairs {
		t.Run(p.Name, func(t *testing.T) {
			t.Parallel()
			out, err := execDiff(t, "--old-sbom", paths[p.Old], "--new-sbom", paths[p.New], "--glsa-dir", glsaDir)
			if err != nil {
				t.Fatalf("diff failed: %v", err)
			}
			var res diff.Result
			if err := json.Unmarshal([]byte(out), &res); err != nil {
				t.Fatalf("output is not JSON: %v", err)
			}
			fixed := map[string]bool{}
			for _, e := range res.Entries {
				if e.Bucket == diff.BucketFixed {
					fixed[e.ID] = true
				}
			}

			expected := map[string]bool{}
			for _, id := range p.ExpectFixed {
				expected[id] = true
				if !fixed[id] {
					t.Errorf("%s is listed as fixed in the release notes but not reported as fixed", id)
				}
			}
			for _, km := range p.KnownMisses {
				for _, id := range km.IDs {
					expected[id] = true
					if fixed[id] {
						t.Logf("known miss %s is now reported as fixed; move it to expect_fixed", id)
					}
				}
			}
			extra := 0
			for id := range fixed {
				if !expected[id] {
					extra++
				}
			}
			t.Logf("%d fixed in notes and found, %d fixed but not in notes", len(p.ExpectFixed), extra)
		})
	}
}

func testCacheDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("FLATCAR_VEX_TEST_CACHE")
	if dir == "" {
		root, err := filepath.Abs(filepath.Join("..", ".."))
		if err != nil {
			t.Fatal(err)
		}
		dir = filepath.Join(root, ".local", "test-cache")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- test cache path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ensureDownload(t *testing.T, path, url, sum string) {
	t.Helper()
	if got, err := fileSHA256(path); err == nil && got == sum {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("download %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download %s: %s", url, resp.Status)
	}
	tmp := path + ".part"
	f, err := os.Create(tmp) // #nosec G304 -- test cache path
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatalf("download %s: %v", url, err)
	}
	if got, err := fileSHA256(tmp); err != nil || got != sum {
		t.Fatalf("download %s: sha256 %s, want %s (%v)", url, got, sum, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func ensureGLSACheckout(t *testing.T, dir, repo, commit string) {
	t.Helper()
	git := func(args ...string) error {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- fixed test arguments
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %v: %w\n%s", args, err, out)
		}
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		if err := git("clone", "--quiet", repo, dir); err != nil {
			t.Fatal(err)
		}
	}
	if git("-C", dir, "checkout", "--quiet", "--detach", commit) == nil {
		return
	}
	if err := git("-C", dir, "fetch", "--quiet", "origin"); err != nil {
		t.Fatal(err)
	}
	if err := git("-C", dir, "checkout", "--quiet", "--detach", commit); err != nil {
		t.Fatal(err)
	}
}
