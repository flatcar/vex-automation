package glsasync

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newTestUpstream creates a throwaway local Git repository (acting as a
// stand-in for the real anongit.gentoo.org remote) containing a single
// glsa-*.xml file, and returns its path. Using a local repo keeps this test
// offline and fast instead of depending on network access.
func newTestUpstream(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run("init", "-b", "master")
	if err := os.WriteFile(filepath.Join(dir, "glsa-202601-01.xml"), []byte("<glsa/>"), 0o600); err != nil {
		t.Fatalf("writing seed file: %v", err)
	}
	run("add", ".")
	run("commit", "-m", "seed")

	return dir
}

// addUpstreamFile commits an additional GLSA file to upstreamDir, simulating
// Gentoo publishing a new advisory.
func addUpstreamFile(t *testing.T, upstreamDir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(upstreamDir, name), []byte("<glsa/>"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	cmd := exec.Command("git", "add", ".")
	cmd.Dir = upstreamDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "commit", "-m", "add "+name)
	cmd.Dir = upstreamDir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
}

func TestSyncClonesThenUpdates(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	// First call: dest doesn't exist yet, should clone.
	res, err := Sync(context.Background(), dest, upstream)
	if err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	if !res.Cloned {
		t.Errorf("expected Cloned=true on first sync, got false")
	}
	if res.FileCount != 1 {
		t.Errorf("FileCount = %d, want 1", res.FileCount)
	}
	if _, err := os.Stat(filepath.Join(dest, "glsa-202601-01.xml")); err != nil {
		t.Errorf("expected seed file to be present: %v", err)
	}

	// Upstream publishes a new advisory.
	addUpstreamFile(t, upstream, "glsa-202601-02.xml")

	// Second call: dest already exists, should update in place.
	res, err = Sync(context.Background(), dest, upstream)
	if err != nil {
		t.Fatalf("Sync (update): %v", err)
	}
	if res.Cloned {
		t.Errorf("expected Cloned=false on second sync, got true")
	}
	if res.FileCount != 2 {
		t.Errorf("FileCount = %d, want 2 after update", res.FileCount)
	}
	if _, err := os.Stat(filepath.Join(dest, "glsa-202601-02.xml")); err != nil {
		t.Errorf("expected new file to be present after update: %v", err)
	}
}

// TestSyncSwitchesRemoteOnRepoChange verifies that calling Sync again with a
// different repoURL against an already-cloned dest re-points the "origin"
// remote and syncs from the new repo, instead of silently continuing to
// fetch from whichever repo dest was originally cloned from.
func TestSyncSwitchesRemoteOnRepoChange(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	upstreamA := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	res, err := Sync(context.Background(), dest, upstreamA)
	if err != nil {
		t.Fatalf("Sync (clone from A): %v", err)
	}
	if !res.Cloned || res.FileCount != 1 {
		t.Fatalf("unexpected first Sync result: %+v", res)
	}

	// A second, independent upstream with different content.
	upstreamB := newTestUpstream(t)
	addUpstreamFile(t, upstreamB, "glsa-202602-01.xml")
	addUpstreamFile(t, upstreamB, "glsa-202602-02.xml")

	res, err = Sync(context.Background(), dest, upstreamB)
	if err != nil {
		t.Fatalf("Sync (switch to B): %v", err)
	}
	if res.Cloned {
		t.Errorf("expected Cloned=false when re-syncing an existing dest, got true")
	}
	// upstreamB has its own seed file plus two more, upstreamA's seed file
	// must be gone after switching remotes and hard-resetting.
	if res.FileCount != 3 {
		t.Errorf("FileCount = %d, want 3 after switching to upstream B", res.FileCount)
	}
	if _, err := os.Stat(filepath.Join(dest, "glsa-202602-02.xml")); err != nil {
		t.Errorf("expected upstream B's file to be present: %v", err)
	}
}

func TestSyncRejectsEmptyDest(t *testing.T) {
	if _, err := Sync(context.Background(), "", "https://example.invalid/glsa.git"); err == nil {
		t.Fatal("expected an error for an empty dest, got nil")
	}
	if _, err := Sync(context.Background(), "   ", "https://example.invalid/glsa.git"); err == nil {
		t.Fatal("expected an error for a whitespace-only dest, got nil")
	}
}

// TestSyncFailsFastOnBadRepo checks that a clone against a nonexistent
// upstream fails with a useful, non-hanging error instead of silently
// succeeding or timing out for the full DefaultTimeout.
func TestSyncFailsFastOnBadRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	badRepo := filepath.Join(t.TempDir(), "does-not-exist.git")

	_, err := Sync(context.Background(), dest, badRepo)
	if err == nil {
		t.Fatal("expected an error cloning a nonexistent repo, got nil")
	}

	// dest must not have been left behind as a half-formed directory that a
	// later Sync call would mistake for something worth updating.
	if _, statErr := os.Stat(filepath.Join(dest, ".git")); statErr == nil {
		t.Errorf("expected no .git dir at %s after a failed clone", dest)
	}
}

// TestSyncRespectsContextTimeout confirms an already-expired context is
// honored (the clone doesn't run to completion regardless of deadline).
func TestSyncRespectsContextTimeout(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	// Ensure the deadline has definitely passed before Sync even checks it.
	<-ctx.Done()

	if _, err := Sync(ctx, dest, upstream); err == nil {
		t.Fatal("expected an error from an already-expired context, got nil")
	}
}

// TestSyncDefaultsRepoURL confirms an empty repoURL falls back to
// DefaultRepoURL rather than being passed through to git verbatim (which
// would fail with a confusing "repository not found" for an empty string).
// An already-expired context keeps this offline: git is invoked (proving
// the empty-repoURL branch didn't short-circuit before reaching it) but is
// killed before any real network I/O completes.
func TestSyncDefaultsRepoURL(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-ctx.Done()

	_, err := Sync(ctx, dest, "")
	if err == nil {
		t.Fatal("expected an error from an already-expired context, got nil")
	}
	if !strings.Contains(err.Error(), DefaultRepoURL) {
		t.Errorf("error %q does not mention DefaultRepoURL %q; empty repoURL may not be defaulting correctly", err, DefaultRepoURL)
	}
}

// TestSyncGitNotFound simulates git being absent from PATH.
func TestSyncGitNotFound(t *testing.T) {
	t.Setenv("PATH", "")

	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	_, err := Sync(context.Background(), dest, "https://example.invalid/glsa.git")
	if err == nil {
		t.Fatal("expected an error when git is not in PATH, got nil")
	}
	if !strings.Contains(err.Error(), "git") {
		t.Errorf("error %q should mention git", err)
	}
}

// TestSyncStatErrorNotNotExist covers the branch where stat()-ing dest/.git
// fails with something other than "does not exist" (e.g. ENOTDIR, when a
// path component above dest is a regular file instead of a directory).
func TestSyncStatErrorNotNotExist(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing blocker file: %v", err)
	}
	dest := filepath.Join(blocker, "child") // "child" can never exist: its parent is a file

	if _, err := Sync(context.Background(), dest, "https://example.invalid/glsa.git"); err == nil {
		t.Fatal("expected an error when a dest path component is a file, got nil")
	}
}

// TestSyncUpdateFailsOnCorruptedCheckout covers update()'s error-wrapping
// paths (fetch/reset failures) by pointing an existing ".git"-containing
// dest at a repo whose ref state git will refuse to operate on cleanly.
func TestSyncUpdateFailsOnCorruptedCheckout(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	if _, err := Sync(context.Background(), dest, upstream); err != nil {
		t.Fatalf("initial Sync (clone): %v", err)
	}

	// Corrupt the checkout's HEAD so a subsequent fetch/reset fails.
	if err := os.WriteFile(filepath.Join(dest, ".git", "HEAD"), []byte("garbage, not a ref\n"), 0o600); err != nil {
		t.Fatalf("corrupting HEAD: %v", err)
	}

	if _, err := Sync(context.Background(), dest, upstream); err == nil {
		t.Fatal("expected an error updating a corrupted checkout, got nil")
	}
}

func TestSyncRefusesNonGitDirectory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	upstream := newTestUpstream(t)
	dest := t.TempDir() // exists, but is not a git checkout

	if err := os.WriteFile(filepath.Join(dest, "unrelated.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatalf("seeding unrelated file: %v", err)
	}

	if _, err := Sync(context.Background(), dest, upstream); err == nil {
		t.Fatalf("expected Sync to refuse a pre-existing non-git directory, got nil error")
	}

	// The unrelated file must be untouched.
	if _, err := os.Stat(filepath.Join(dest, "unrelated.txt")); err != nil {
		t.Errorf("unrelated file should have been left alone: %v", err)
	}
}
