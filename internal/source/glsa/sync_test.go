package glsa

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// newTestUpstream creates a throwaway local Git repository (acting as a
// stand-in for the real anongit.gentoo.org remote) containing a single
// glsa-*.xml file, and returns its path. Using a local repo keeps this test
// offline and fast instead of depending on network access.
//
// go-git reads a local repository by running git's upload-pack, so these
// tests need git installed even though Sync does not for remote URLs.
func newTestUpstream(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	if _, err := git.PlainInit(dir, false); err != nil {
		t.Fatalf("git init: %v", err)
	}
	addUpstreamFile(t, dir, "glsa-202601-01.xml")
	return dir
}

// addUpstreamFile commits an additional GLSA file to upstreamDir, simulating
// Gentoo publishing a new advisory.
func addUpstreamFile(t *testing.T, upstreamDir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(upstreamDir, name), []byte("<glsa/>"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	commitAll(t, upstreamDir, "add "+name)
}

// commitAll commits every file in dir, as "git add . && git commit" would.
func commitAll(t *testing.T, dir, message string) {
	t.Helper()
	repo, err := git.PlainOpen(dir)
	if err != nil {
		t.Fatalf("opening %s: %v", dir, err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree of %s: %v", dir, err)
	}
	if err := worktree.AddWithOptions(&git.AddOptions{All: true}); err != nil {
		t.Fatalf("git add: %v", err)
	}
	author := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}
	if _, err := worktree.Commit(message, &git.CommitOptions{Author: author, AllowEmptyCommits: true}); err != nil {
		t.Fatalf("git commit: %v", err)
	}
}

func TestSyncClonesThenUpdates(t *testing.T) {
	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	// First call: dest doesn't exist yet, should clone.
	res, err := Sync(context.Background(), dest, upstream, nil)
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
	res, err = Sync(context.Background(), dest, upstream, nil)
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

// TestSyncMatchesUpstreamExactly checks that an update leaves exactly
// upstream's files: files removed upstream disappear, changed files are
// restored, and files git does not track (say, an advisory left behind by
// an interrupted run) are removed too, so LoadDir never reads them.
func TestSyncMatchesUpstreamExactly(t *testing.T) {
	upstream := newTestUpstream(t)
	addUpstreamFile(t, upstream, "glsa-202601-02.xml")
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	untracked := filepath.Join(dest, "2099", "glsa-209901-01.xml")
	if err := os.MkdirAll(filepath.Dir(untracked), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(untracked, []byte("<glsa/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "glsa-202601-01.xml"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(upstream, "glsa-202601-02.xml")); err != nil {
		t.Fatal(err)
	}
	commitAll(t, upstream, "remove glsa-202601-02.xml")

	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (update): %v", err)
	}
	if _, err := os.Stat(untracked); !os.IsNotExist(err) {
		t.Errorf("untracked advisory still present (err = %v)", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "glsa-202601-01.xml")); string(got) != "<glsa/>" {
		t.Errorf("tracked file = %q, want it restored", got)
	}
	if _, err := os.Stat(filepath.Join(dest, "glsa-202601-02.xml")); !os.IsNotExist(err) {
		t.Errorf("file removed upstream still present (err = %v)", err)
	}
}

// TestSyncUpdatesGitCLIClone checks that mirrors made by "git clone", as
// earlier versions of sync-glsa did, can be updated. git clone writes
// refs/remotes/origin/HEAD as a symbolic ref.
func TestSyncUpdatesGitCLIClone(t *testing.T) {
	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	cmd := exec.Command("git", "clone", "--quiet", "--no-local", upstream, dest) // #nosec G204 -- test arguments
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v: %s", err, out)
	}

	for _, name := range []string{"glsa-202601-02.xml", "glsa-202601-03.xml"} {
		addUpstreamFile(t, upstream, name)
		res, err := Sync(context.Background(), dest, upstream, nil)
		if err != nil {
			t.Fatalf("Sync after adding %s: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Errorf("%s missing after update (result %+v)", name, res)
		}
	}
}

// TestSyncReplacesDirectoryWithFile checks the rare case where upstream
// turns a directory into a file while the mirror has an untracked file in
// that directory: like "git reset --hard", the file wins.
func TestSyncReplacesDirectoryWithFile(t *testing.T) {
	upstream := newTestUpstream(t)
	if err := os.MkdirAll(filepath.Join(upstream, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	addUpstreamFile(t, upstream, filepath.Join("d", "x"))
	addUpstreamFile(t, upstream, "glsa-202601-02.xml")
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "d", "u"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"d", "glsa-202601-02.xml"} {
		if err := os.RemoveAll(filepath.Join(upstream, name)); err != nil {
			t.Fatal(err)
		}
	}
	commitAll(t, upstream, "remove d/ and glsa-202601-02.xml")
	addUpstreamFile(t, upstream, "d")

	res, err := Sync(context.Background(), dest, upstream, nil)
	if err != nil {
		t.Fatalf("Sync (update): %v", err)
	}
	if info, err := os.Stat(filepath.Join(dest, "d")); err != nil || info.IsDir() {
		t.Errorf("d should be a file after the update (err = %v)", err)
	}
	if res.FileCount != 1 {
		t.Errorf("FileCount = %d, want 1 (the GLSA removed upstream must be gone)", res.FileCount)
	}
}

// TestSyncStaysInsideDest checks that a hostile upstream cannot make an
// update delete files outside dest: it first tracks a symlink to a
// directory outside, then replaces the symlink with a directory whose
// file has the same name as a directory outside.
func TestSyncStaysInsideDest(t *testing.T) {
	upstream := newTestUpstream(t)
	if err := os.Symlink("../outside", filepath.Join(upstream, "a")); err != nil {
		t.Fatal(err)
	}
	commitAll(t, upstream, "add symlink a")
	parent := t.TempDir()
	outsideFile := filepath.Join(parent, "outside", "keep", "data")
	if err := os.MkdirAll(filepath.Dir(outsideFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideFile, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(parent, "glsa-mirror")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	if err := os.Remove(filepath.Join(upstream, "a")); err != nil {
		t.Fatal(err)
	}
	commitAll(t, upstream, "remove symlink a")
	if err := os.MkdirAll(filepath.Join(upstream, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	addUpstreamFile(t, upstream, filepath.Join("a", "keep"))

	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (update): %v", err)
	}
	if got, err := os.ReadFile(outsideFile); err != nil || string(got) != "precious" {
		t.Errorf("file outside dest = %q, %v; want it untouched", got, err)
	}
	if info, err := os.Lstat(filepath.Join(dest, "a", "keep")); err != nil || !info.Mode().IsRegular() {
		t.Errorf("a/keep should be a file inside dest (err = %v)", err)
	}
}

// TestSyncRemovesSymlinkInsideDest checks that a symlink pointing inside
// the mirror (here at .git) is replaced, not followed, when upstream turns
// it into a directory.
func TestSyncRemovesSymlinkInsideDest(t *testing.T) {
	upstream := newTestUpstream(t)
	if err := os.Symlink(".git", filepath.Join(upstream, "a")); err != nil {
		t.Fatal(err)
	}
	commitAll(t, upstream, "add symlink a")
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	if err := os.Remove(filepath.Join(upstream, "a")); err != nil {
		t.Fatal(err)
	}
	commitAll(t, upstream, "remove symlink a")
	if err := os.MkdirAll(filepath.Join(upstream, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	addUpstreamFile(t, upstream, filepath.Join("a", "objects"))

	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (update): %v", err)
	}
	if info, err := os.Stat(filepath.Join(dest, ".git", "objects")); err != nil || !info.IsDir() {
		t.Errorf(".git/objects must survive (err = %v)", err)
	}
	if info, err := os.Lstat(filepath.Join(dest, "a", "objects")); err != nil || !info.Mode().IsRegular() {
		t.Errorf("a/objects should be a file inside dest (err = %v)", err)
	}
}

// TestSyncReplacesFileWithDirectory checks that an untracked file where
// upstream now needs a directory is replaced, as "git reset --hard" does.
func TestSyncReplacesFileWithDirectory(t *testing.T) {
	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "202611"), []byte("stray"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(upstream, "202611"), 0o755); err != nil {
		t.Fatal(err)
	}
	addUpstreamFile(t, upstream, filepath.Join("202611", "glsa-202611-01.xml"))

	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (update): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "202611", "glsa-202611-01.xml")); err != nil {
		t.Errorf("new GLSA should be checked out: %v", err)
	}
}

// TestSyncRemovesFilesFromAPartialFailedUpdate checks that an advisory a
// failed update managed to write is removed on retry once upstream has
// withdrawn it.
func TestSyncRemovesFilesFromAPartialFailedUpdate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	addUpstreamFile(t, upstream, "glsa-202601-02.xml")
	if err := os.MkdirAll(filepath.Join(upstream, "z"), 0o755); err != nil {
		t.Fatal(err)
	}
	addUpstreamFile(t, upstream, filepath.Join("z", "notes"))

	// A read-only z/ lets the reset write glsa-202601-02.xml, then fail.
	blocked := filepath.Join(dest, "z")
	if err := os.Mkdir(blocked, 0o555); err != nil {
		t.Fatal(err)
	}
	_, err := Sync(context.Background(), dest, upstream, nil)
	if chmodErr := os.Chmod(blocked, 0o755); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	if err == nil {
		t.Fatal("expected the update to fail on the read-only directory")
	}
	if _, err := os.Stat(filepath.Join(dest, "glsa-202601-02.xml")); err != nil {
		t.Fatalf("test setup: the failed update should have written the new GLSA: %v", err)
	}

	if err := os.Remove(filepath.Join(upstream, "glsa-202601-02.xml")); err != nil {
		t.Fatal(err)
	}
	commitAll(t, upstream, "withdraw glsa-202601-02.xml")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (retry): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "glsa-202601-02.xml")); !os.IsNotExist(err) {
		t.Errorf("withdrawn glsa-202601-02.xml must be removed on retry (stat err = %v)", err)
	}
}

// TestSyncRecoversFromFailedReset checks that a retry after a failed
// update still removes advisories that upstream deleted, so a withdrawn
// GLSA can't survive as an untracked file.
func TestSyncRecoversFromFailedReset(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	upstream := newTestUpstream(t)
	addUpstreamFile(t, upstream, "glsa-202601-02.xml")
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	cloned, err := Sync(context.Background(), dest, upstream, nil)
	if err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	if err := os.Remove(filepath.Join(upstream, "glsa-202601-02.xml")); err != nil {
		t.Fatal(err)
	}
	commitAll(t, upstream, "withdraw glsa-202601-02.xml")

	// A read-only checkout (with a writable .git) makes the reset fail.
	if err := os.Chmod(dest, 0o555); err != nil {
		t.Fatal(err)
	}
	_, err = Sync(context.Background(), dest, upstream, nil)
	if chmodErr := os.Chmod(dest, 0o755); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	if err == nil {
		t.Fatal("expected the update of a read-only checkout to fail")
	}

	res, err := Sync(context.Background(), dest, upstream, nil)
	if err != nil {
		t.Fatalf("Sync (retry): %v", err)
	}
	if res.FileCount != 1 {
		t.Errorf("FileCount = %d after retry, want 1 (withdrawn GLSA must be removed)", res.FileCount)
	}
	if res.OldCommit != cloned.NewCommit || res.NewCommit == res.OldCommit {
		t.Errorf("retry went from %s to %s, want from the cloned commit %s to a new one", res.OldCommit, res.NewCommit, cloned.NewCommit)
	}
}

// TestSyncReportsUpdateErrors checks that a failing fetch during an
// update is reported as such.
func TestSyncReportsUpdateErrors(t *testing.T) {
	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	_, err := Sync(context.Background(), dest, filepath.Join(t.TempDir(), "missing"), nil)
	if err == nil || !strings.Contains(err.Error(), "fetching updates in "+dest) {
		t.Fatalf("err = %v, want a fetch error naming %s", err, dest)
	}
}

// TestSyncSwitchesRemoteOnRepoChange verifies that calling Sync again with a
// different repoURL against an already-cloned dest re-points the "origin"
// remote and syncs from the new repo, instead of silently continuing to
// fetch from whichever repo dest was originally cloned from.
func TestSyncSwitchesRemoteOnRepoChange(t *testing.T) {
	upstreamA := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	res, err := Sync(context.Background(), dest, upstreamA, nil)
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

	res, err = Sync(context.Background(), dest, upstreamB, nil)
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
	if _, err := Sync(context.Background(), "", "https://example.invalid/glsa.git", nil); err == nil {
		t.Fatal("expected an error for an empty dest, got nil")
	}
	if _, err := Sync(context.Background(), "   ", "https://example.invalid/glsa.git", nil); err == nil {
		t.Fatal("expected an error for a whitespace-only dest, got nil")
	}
}

// TestSyncFailsFastOnBadRepo checks that a clone against a nonexistent
// upstream fails with a useful, non-hanging error instead of silently
// succeeding or timing out for the full DefaultTimeout.
func TestSyncFailsFastOnBadRepo(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	badRepo := filepath.Join(t.TempDir(), "does-not-exist.git")

	_, err := Sync(context.Background(), dest, badRepo, nil)
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
	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	// Ensure the deadline has definitely passed before Sync even checks it.
	<-ctx.Done()

	if _, err := Sync(ctx, dest, upstream, nil); err == nil {
		t.Fatal("expected an error from an already-expired context, got nil")
	}
}

// TestSyncDefaultsRepoURL confirms an empty repoURL falls back to
// DefaultRepoURL rather than being passed through to git verbatim (which
// would fail with a confusing "repository not found" for an empty string).
// An already-expired context keeps this offline: the clone is started
// (proving the empty-repoURL branch didn't short-circuit before reaching
// it) but stops before any network I/O.
func TestSyncDefaultsRepoURL(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-ctx.Done()

	_, err := Sync(ctx, dest, "", nil)
	if err == nil {
		t.Fatal("expected an error from an already-expired context, got nil")
	}
	if !strings.Contains(err.Error(), DefaultRepoURL) {
		t.Errorf("error %q does not mention DefaultRepoURL %q; empty repoURL may not be defaulting correctly", err, DefaultRepoURL)
	}
}

// TestSyncNeedsNoGitBinary checks that syncing from a remote URL never
// runs git: with an empty PATH the error is a network one.
func TestSyncNeedsNoGitBinary(t *testing.T) {
	t.Setenv("PATH", "")

	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	_, err := Sync(context.Background(), dest, "https://127.0.0.1:1/glsa.git", nil)
	if err == nil {
		t.Fatal("expected an error cloning from a closed port, got nil")
	}
	if strings.Contains(err.Error(), "executable file not found") {
		t.Errorf("Sync tried to run a program: %v", err)
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

	if _, err := Sync(context.Background(), dest, "https://example.invalid/glsa.git", nil); err == nil {
		t.Fatal("expected an error when a dest path component is a file, got nil")
	}
}

// TestSyncUpdateFailsOnCorruptedCheckout checks that a checkout whose HEAD
// is garbage is reported instead of updated.
func TestSyncUpdateFailsOnCorruptedCheckout(t *testing.T) {
	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("initial Sync (clone): %v", err)
	}

	// Corrupt the checkout's HEAD so opening the checkout fails.
	if err := os.WriteFile(filepath.Join(dest, ".git", "HEAD"), []byte("garbage, not a ref\n"), 0o600); err != nil {
		t.Fatalf("corrupting HEAD: %v", err)
	}

	_, err := Sync(context.Background(), dest, upstream, nil)
	if err == nil || !strings.Contains(err.Error(), dest) {
		t.Fatalf("Sync error = %v, want an error naming %s", err, dest)
	}
}

func TestSyncRefusesNonGitDirectory(t *testing.T) {
	upstream := newTestUpstream(t)
	dest := t.TempDir() // exists, but is not a git checkout

	if err := os.WriteFile(filepath.Join(dest, "unrelated.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatalf("seeding unrelated file: %v", err)
	}

	if _, err := Sync(context.Background(), dest, upstream, nil); err == nil {
		t.Fatalf("expected Sync to refuse a pre-existing non-git directory, got nil error")
	}

	// The unrelated file must be untouched.
	if _, err := os.Stat(filepath.Join(dest, "unrelated.txt")); err != nil {
		t.Errorf("unrelated file should have been left alone: %v", err)
	}
}

func TestSyncReportsStepsAndCommits(t *testing.T) {
	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	var progress bytes.Buffer
	first, err := Sync(context.Background(), dest, upstream, &progress)
	if err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	if want := "Cloning " + upstream + " into " + dest; !strings.Contains(progress.String(), want) {
		t.Errorf("progress = %q, want it to contain %q", progress.String(), want)
	}
	if first.OldCommit != "" || first.NewCommit == "" {
		t.Errorf("clone commits = %q -> %q, want \"\" -> a commit", first.OldCommit, first.NewCommit)
	}

	progress.Reset()
	same, err := Sync(context.Background(), dest, upstream, &progress)
	if err != nil {
		t.Fatalf("Sync (no change): %v", err)
	}
	if want := "Fetching updates from " + upstream; !strings.Contains(progress.String(), want) {
		t.Errorf("progress = %q, want it to contain %q", progress.String(), want)
	}
	if same.OldCommit != first.NewCommit || same.NewCommit != first.NewCommit {
		t.Errorf("unchanged commits = %q -> %q, want %q twice", same.OldCommit, same.NewCommit, first.NewCommit)
	}

	addUpstreamFile(t, upstream, "glsa-202601-02.xml")
	updated, err := Sync(context.Background(), dest, upstream, nil)
	if err != nil {
		t.Fatalf("Sync (update): %v", err)
	}
	if updated.OldCommit != first.NewCommit || updated.NewCommit == first.NewCommit {
		t.Errorf("updated commits = %q -> %q, want %q -> a new commit", updated.OldCommit, updated.NewCommit, first.NewCommit)
	}
}

// An interrupted clone can leave a .git with no commit yet; a later Sync
// must still update it.
func TestSyncUpdatesCheckoutWithUnbornHead(t *testing.T) {
	upstream := newTestUpstream(t)
	dest := t.TempDir()
	repo, err := git.PlainInit(dest, false)
	if err != nil {
		t.Fatalf("git init: %v", err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{upstream}}); err != nil {
		t.Fatalf("git remote add: %v", err)
	}

	res, err := Sync(context.Background(), dest, upstream, nil)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.Cloned || res.OldCommit != "" || res.NewCommit == "" || res.FileCount != 1 {
		t.Errorf("Result = %+v, want an update from no commit to one commit with 1 file", res)
	}
}

func TestMakeRoomForFilesRejectsUnsafePaths(t *testing.T) {
	root := t.TempDir()
	gitObjects := filepath.Join(root, ".git", "objects")
	if err := os.MkdirAll(gitObjects, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{".git/objects", "a/.GIT/x", "a/../b", "./a", "a//b"} {
		if err := makeRoomForFiles(context.Background(), root, []string{path}); err == nil {
			t.Errorf("makeRoomForFiles(%q) = nil, want an error", path)
		}
	}
	if _, err := os.Stat(gitObjects); err != nil {
		t.Errorf(".git/objects must survive: %v", err)
	}
}

// TestSyncKeepsOriginSettings checks that an update only changes origin's
// URL, like "git remote set-url", and keeps its other settings.
func TestSyncKeepsOriginSettings(t *testing.T) {
	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	configPath := filepath.Join(dest, ".git", "config")
	gitConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	settings := "[remote \"origin\"]\n\ttagopt = --no-tags\n\tpushurl = https://push.example/glsa.git\n"
	if err := os.WriteFile(configPath, append(gitConfig, settings...), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (update): %v", err)
	}
	gitConfig, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gitConfig), "tagopt = --no-tags") {
		t.Errorf("origin lost its tagopt setting:\n%s", gitConfig)
	}
	if !strings.Contains(string(gitConfig), "pushurl = https://push.example/glsa.git") ||
		strings.Count(string(gitConfig), "\turl = ") != 1 {
		t.Errorf("origin should keep one url and its separate pushurl:\n%s", gitConfig)
	}
}

func TestSyncIgnoresURLRewritesOnRepoChange(t *testing.T) {
	oldServerHits := 0
	oldServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		oldServerHits++
		http.Error(w, "broken", http.StatusInternalServerError)
	}))
	t.Cleanup(oldServer.Close)
	newServerHits := 0
	newServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		newServerHits++
		http.Error(w, "broken", http.StatusInternalServerError)
	}))
	t.Cleanup(newServer.Close)

	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	// Local rules that rewrite both the current origin and the new
	// repository to the old server.
	configPath := filepath.Join(dest, ".git", "config")
	gitConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	rules := fmt.Sprintf("[url %q]\n\tinsteadOf = %s\n[url %q]\n\tinsteadOf = %s\n",
		oldServer.URL+"/a", upstream, oldServer.URL+"/b", newServer.URL)
	if err := os.WriteFile(configPath, append(gitConfig, rules...), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Sync(context.Background(), dest, newServer.URL+"/glsa.git", nil); err == nil {
		t.Fatal("expected an error from a failing server")
	}
	if oldServerHits != 0 || newServerHits == 0 {
		t.Errorf("old server got %d requests, new server %d; want only the new server", oldServerHits, newServerHits)
	}
	gitConfig, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gitConfig), "url = "+newServer.URL+"/glsa.git") {
		t.Errorf("origin should point at %s/glsa.git:\n%s", newServer.URL, gitConfig)
	}
}

func TestReplaceFile(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	if err := os.WriteFile(config, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(config, []byte("new")); err != nil {
		t.Fatalf("replaceFile: %v", err)
	}
	if got, _ := os.ReadFile(config); string(got) != "new" {
		t.Errorf("config = %q, want %q", got, "new")
	}
	if err := os.Chmod(config, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(config, []byte("newer")); err != nil {
		t.Fatalf("replaceFile: %v", err)
	}
	created := filepath.Join(dir, "created")
	if err := replaceFile(created, []byte("new")); err != nil {
		t.Fatalf("replaceFile: %v", err)
	}
	for path, want := range map[string]os.FileMode{config: 0o600, created: 0o600} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: mode %v (err %v), want %v", path, info.Mode().Perm(), err, want)
		}
	}

	// A non-empty directory can't be renamed over, so the swap fails.
	blocked := filepath.Join(dir, "blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(blocked, []byte("new")); err == nil {
		t.Error("expected an error replacing a non-empty directory")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(leftovers) != 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
}

func TestSyncReportsDiscardedLocalChanges(t *testing.T) {
	upstream := newTestUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")
	if _, err := Sync(context.Background(), dest, upstream, nil); err != nil {
		t.Fatalf("Sync (clone): %v", err)
	}
	for name, content := range map[string]string{"glsa-202601-01.xml": "tampered", "glsa-209901-01.xml": "<glsa/>"} {
		if err := os.WriteFile(filepath.Join(dest, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var progress bytes.Buffer
	if _, err := Sync(context.Background(), dest, upstream, &progress); err != nil {
		t.Fatalf("Sync (update): %v", err)
	}
	if want := "Discarding 2 local change(s) in " + dest; !strings.Contains(progress.String(), want) {
		t.Errorf("progress = %q, want it to contain %q", progress.String(), want)
	}
	progress.Reset()
	if _, err := Sync(context.Background(), dest, upstream, &progress); err != nil {
		t.Fatalf("Sync (clean update): %v", err)
	}
	if strings.Contains(progress.String(), "Discarding") {
		t.Errorf("a clean mirror should report no discarded changes, got %q", progress.String())
	}
}

func TestDownloadProgressOnlyForTerminals(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("opening %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = devNull.Close() })
	for name, w := range map[string]io.Writer{"nil": nil, "buffer": &bytes.Buffer{}, os.DevNull: devNull} {
		if got := (syncer{progress: w}).terminal(); got != nil {
			t.Errorf("%s: terminal() = %v, want nil", name, got)
		}
	}

	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("no terminal available: %v", err)
	}
	t.Cleanup(func() { _ = tty.Close() })
	if got := (syncer{progress: tty}).terminal(); got != tty {
		t.Errorf("terminal: terminal() = %v, want the terminal", got)
	}
}
