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
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
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
	// OldCommit and NewCommit are the checked-out commit before and after
	// syncing. OldCommit is empty after a clone, or when an existing
	// checkout had no commit yet (e.g. an interrupted clone).
	OldCommit string
	NewCommit string
}

// Sync ensures dest contains an up-to-date checkout of the GLSA corpus from
// repoURL (DefaultRepoURL if empty), cloning it if dest doesn't exist yet or
// fast-forwarding it in place otherwise. It is safe to call repeatedly (e.g.
// from a cron job or CI step) to keep a local mirror fresh.
//
// dest must either not exist (it will be created) or already be a Git
// checkout of the same repository; Sync refuses to clobber a directory that
// exists, is non-empty, and isn't such a checkout (git's own clone-into-a-
// non-empty-directory error enforces this, though an empty pre-existing
// directory is accepted).
//
// If progress is non-nil, Sync writes each step to it, plus git's own
// progress meter when progress is a terminal.
func Sync(ctx context.Context, dest, repoURL string, progress io.Writer) (Result, error) {
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

	g := git{progress: progress}
	gitDir := filepath.Join(dest, ".git")
	_, statErr := os.Stat(gitDir)
	switch {
	case os.IsNotExist(statErr):
		if err := g.clone(ctx, dest, repoURL); err != nil {
			return Result{}, err
		}
		return finish(ctx, dest, true, "")
	case statErr != nil:
		return Result{}, fmt.Errorf("glsasync: checking %s: %w", gitDir, statErr)
	default:
		old, err := headCommit(ctx, dest)
		if err != nil {
			return Result{}, err
		}
		if err := g.update(ctx, dest, repoURL); err != nil {
			return Result{}, err
		}
		return finish(ctx, dest, false, old)
	}
}

func finish(ctx context.Context, dest string, cloned bool, oldCommit string) (Result, error) {
	n, err := countGLSAFiles(dest)
	if err != nil {
		return Result{}, err
	}
	head, err := headCommit(ctx, dest)
	if err != nil {
		return Result{}, err
	}
	return Result{Dest: dest, Cloned: cloned, FileCount: n, OldCommit: oldCommit, NewCommit: head}, nil
}

// headCommit returns the commit checked out in dest, or "" if HEAD has no
// commit yet. An invalid repository is an error.
func headCommit(ctx context.Context, dest string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", dest, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return strings.TrimSpace(string(out)), nil
	case errors.As(err, &exit) && exit.ExitCode() == 1 && stderr.Len() == 0:
		return "", nil
	case stderr.Len() > 0:
		return "", fmt.Errorf("glsasync: reading HEAD of %s: %w: %s", dest, err, strings.TrimSpace(stderr.String()))
	default:
		return "", fmt.Errorf("glsasync: reading HEAD of %s: %w", dest, err)
	}
}

// redact drops any user:password part from repoURL for display.
func redact(repoURL string) string {
	u, err := url.Parse(repoURL)
	if err != nil || u.User == nil {
		return repoURL
	}
	u.User = nil
	return u.String()
}

// git runs git commands, reporting steps (and, on a terminal, git's
// progress meter) to progress.
type git struct {
	progress io.Writer
}

func (g git) step(format string, args ...any) {
	if g.progress != nil {
		_, _ = fmt.Fprintf(g.progress, format+"\n", args...)
	}
}

// networkArgs inserts --progress after the git subcommand when progress is
// a terminal, so git shows its meter even though its stderr is a pipe.
func (g git) networkArgs(args ...string) []string {
	if f, ok := g.progress.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return append([]string{args[0], "--progress"}, args[1:]...)
	}
	return args
}

func (g git) clone(ctx context.Context, dest, repoURL string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("glsasync: creating parent of %s: %w", dest, err)
	}
	g.step("Cloning %s into %s...", redact(repoURL), dest)
	if err := g.run(ctx, "", g.networkArgs("clone", "--depth", "1", repoURL, dest)...); err != nil {
		return fmt.Errorf("glsasync: cloning %s into %s: %w", redact(repoURL), dest, err)
	}
	return nil
}

// update fast-forwards an existing shallow clone to the latest upstream
// commit. It fetches upstream's HEAD and hard-resets to it (one network
// round-trip, as anongit.gentoo.org can be slow) rather than running
// "git pull" directly, since a plain pull's merge step is unnecessary (and
// occasionally fragile) for a read-only mirror that should always exactly
// match upstream.
//
// It also reconciles the "origin" remote's URL with repoURL first: without
// this, calling Sync again with a different --repo than the one dest was
// originally cloned from would silently keep fetching from the old remote
// instead of honoring the new one.
func (g git) update(ctx context.Context, dest, repoURL string) error {
	if err := g.setOriginURL(ctx, dest, repoURL); err != nil {
		return err
	}
	g.step("Fetching updates from %s into %s...", redact(repoURL), dest)
	if err := g.run(ctx, dest, g.networkArgs("fetch", "--depth", "1", "origin", "HEAD")...); err != nil {
		return fmt.Errorf("glsasync: fetching updates in %s: %w", dest, err)
	}
	if err := g.run(ctx, dest, "reset", "--hard", "FETCH_HEAD"); err != nil {
		return fmt.Errorf("glsasync: updating %s to upstream HEAD: %w", dest, err)
	}
	return nil
}

// setOriginURL points dest's "origin" remote at repoURL, so a later Sync
// call with a different --repo doesn't silently keep updating from
// whatever remote the directory happened to be cloned from originally.
func (g git) setOriginURL(ctx context.Context, dest, repoURL string) error {
	if err := g.run(ctx, dest, "remote", "set-url", "origin", repoURL); err != nil {
		return fmt.Errorf("glsasync: pointing origin at %s in %s: %w", redact(repoURL), dest, err)
	}
	return nil
}

// run runs git with args, in dir if non-empty, returning stderr output
// wrapped into the error on failure. With --progress, stderr is also
// passed through to g.progress.
func (g git) run(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if len(args) > 1 && args[1] == "--progress" {
		cmd.Stderr = io.MultiWriter(&stderr, g.progress)
	}
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
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
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
