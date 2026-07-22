// Package glsasync fetches and updates a local mirror of the upstream
// Gentoo GLSA corpus, so a user doesn't have to source or maintain their
// own copy of the metadata/glsa directory by hand.
//
// It shells out to the system "git" binary rather than reimplementing Git
// or a GLSA-specific transport: the upstream corpus is published as a
// normal Git repository (see DefaultRepoURL), and Git already does
// efficient incremental fetching well. This mirrors the general project
// principle (see docs/plan.md) of wrapping existing tools instead of
// re-deriving their functionality from scratch wherever avoidable.
package glsasync

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultRepoURL is Gentoo's canonical GLSA data repository. It is the same
// upstream source Flatcar's own scripts repo mirrors via rsync (see
// docs/current-state.md §6), just fetched over Git instead.
const DefaultRepoURL = "https://anongit.gentoo.org/git/data/glsa.git"

// DefaultTimeout bounds how long a clone or update may take before Sync
// gives up, so a network problem fails fast instead of hanging forever.
const DefaultTimeout = 5 * time.Minute

// Result reports the outcome of a Sync call.
type Result struct {
	// Dest is the local directory the GLSA corpus was synced into.
	Dest string
	// Cloned is true if this call performed a fresh clone (dest didn't
	// already contain a checkout); false if it updated an existing one.
	Cloned bool
	// FileCount is the number of glsa-*.xml files present in Dest after
	// syncing.
	FileCount int
}

// Sync ensures dest contains an up-to-date checkout of the GLSA corpus from
// repoURL (DefaultRepoURL if empty), cloning it if dest doesn't exist yet or
// fast-forwarding it in place otherwise. It is safe to call repeatedly (e.g.
// from a cron job or CI step) to keep a local mirror fresh.
//
// dest must either not exist (it will be created) or already be a Git
// checkout of the same repository; Sync refuses to touch a directory that
// exists but isn't one, to avoid silently clobbering unrelated files.
func Sync(ctx context.Context, dest, repoURL string) (Result, error) {
	if strings.TrimSpace(dest) == "" {
		return Result{}, fmt.Errorf("glsasync: dest must not be empty")
	}
	if repoURL == "" {
		repoURL = DefaultRepoURL
	}

	if _, err := exec.LookPath("git"); err != nil {
		return Result{}, fmt.Errorf("glsasync: \"git\" not found in PATH: %w", err)
	}

	// Only impose DefaultTimeout if the caller hasn't already set their own
	// deadline; this lets a CLI flag (or a test) tighten or loosen it
	// without needing a separate Sync parameter.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}

	gitDir := filepath.Join(dest, ".git")
	_, statErr := os.Stat(gitDir)
	switch {
	case os.IsNotExist(statErr):
		if err := clone(ctx, dest, repoURL); err != nil {
			return Result{}, err
		}
		return finish(dest, true)
	case statErr != nil:
		return Result{}, fmt.Errorf("glsasync: checking %s: %w", gitDir, statErr)
	default:
		if err := update(ctx, dest, repoURL); err != nil {
			return Result{}, err
		}
		return finish(dest, false)
	}
}

func finish(dest string, cloned bool) (Result, error) {
	n, err := countGLSAFiles(dest)
	if err != nil {
		return Result{}, err
	}
	return Result{Dest: dest, Cloned: cloned, FileCount: n}, nil
}

func clone(ctx context.Context, dest, repoURL string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("glsasync: creating parent of %s: %w", dest, err)
	}
	if err := runGit(ctx, "", "clone", "--depth", "1", repoURL, dest); err != nil {
		return fmt.Errorf("glsasync: cloning %s into %s: %w", repoURL, dest, err)
	}
	return nil
}

// update fast-forwards an existing shallow clone to the latest upstream
// commit. It fetches then hard-resets to origin/HEAD rather than running
// "git pull" directly, since a plain pull's merge step is unnecessary (and
// occasionally fragile) for a read-only mirror that should always exactly
// match upstream.
//
// It also reconciles the "origin" remote's URL with repoURL first: without
// this, calling Sync again with a different --repo than the one dest was
// originally cloned from would silently keep fetching from the old remote
// instead of honoring the new one.
func update(ctx context.Context, dest, repoURL string) error {
	if err := setOriginURL(ctx, dest, repoURL); err != nil {
		return err
	}
	if err := runGit(ctx, dest, "fetch", "--depth", "1", "origin"); err != nil {
		return fmt.Errorf("glsasync: fetching updates in %s: %w", dest, err)
	}
	if err := runGit(ctx, dest, "remote", "set-head", "origin", "-a"); err != nil {
		return fmt.Errorf("glsasync: resolving origin/HEAD in %s: %w", dest, err)
	}
	if err := runGit(ctx, dest, "reset", "--hard", "origin/HEAD"); err != nil {
		return fmt.Errorf("glsasync: updating %s to origin/HEAD: %w", dest, err)
	}
	return nil
}

// setOriginURL points dest's "origin" remote at repoURL, so a later Sync
// call with a different --repo doesn't silently keep updating from
// whatever remote the directory happened to be cloned from originally.
func setOriginURL(ctx context.Context, dest, repoURL string) error {
	if err := runGit(ctx, dest, "remote", "set-url", "origin", repoURL); err != nil {
		return fmt.Errorf("glsasync: pointing origin at %s in %s: %w", repoURL, dest, err)
	}
	return nil
}

// runGit runs git with args, in dir if non-empty, returning stderr output
// wrapped into the error on failure.
func runGit(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

// countGLSAFiles returns the number of glsa-*.xml files anywhere under dir,
// ignoring the .git directory itself (which never contains matching names
// but isn't worth descending into either).
func countGLSAFiles(dir string) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, "glsa-") && strings.HasSuffix(name, ".xml") {
			n++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("glsasync: counting GLSA files in %s: %w", dir, err)
	}
	return n, nil
}
