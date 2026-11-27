// Package glsasync keeps a local copy of Gentoo's GLSA repository up to
// date by running the system "git" binary. It backs the sync-glsa command,
// whose output directory is what generate and diff read with --glsa-dir.
package glsasync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/flatcar/vex-automation/internal/glsa"
)

// DefaultRepoURL is Gentoo's GLSA repository, the same data Flatcar's
// scripts repository mirrors.
const DefaultRepoURL = "https://anongit.gentoo.org/git/data/glsa.git"

// DefaultTimeout is how long Sync may take when the caller's context has
// no deadline, so a network problem fails instead of hanging.
const DefaultTimeout = 5 * time.Minute

// Result describes what Sync did.
type Result struct {
	Dest      string
	Cloned    bool // true for a new clone, false for an update
	FileCount int  // glsa-*.xml files in Dest after syncing
	// OldCommit is the commit before an update; empty after a clone, or if
	// the existing checkout had no commit (e.g. an interrupted clone).
	OldCommit string
	NewCommit string
}

// Sync clones repoURL (DefaultRepoURL if empty) into dest, or, if dest is
// already a clone, updates it to the latest upstream commit. Updating
// resets the checkout, discarding local changes, so dest should be a
// dedicated mirror. Git refuses to clone into a non-empty directory that
// is not a clone, so such a directory is left untouched.
//
// If progress is not nil, Sync reports each step to it, plus git's own
// progress meter if progress is a terminal.
func Sync(ctx context.Context, dest, repoURL string, progress io.Writer) (Result, error) {
	if strings.TrimSpace(dest) == "" {
		return Result{}, errors.New("glsasync: dest must not be empty")
	}
	if repoURL == "" {
		repoURL = DefaultRepoURL
	}
	if _, err := exec.LookPath("git"); err != nil {
		return Result{}, fmt.Errorf("glsasync: \"git\" not found in PATH: %w", err)
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}

	g := git{progress: progress}
	gitDir := filepath.Join(dest, ".git")
	_, err := os.Stat(gitDir)
	switch {
	case os.IsNotExist(err):
		if err := g.clone(ctx, dest, repoURL); err != nil {
			return Result{}, err
		}
		return summarize(ctx, dest, true, "")
	case err != nil:
		return Result{}, fmt.Errorf("glsasync: checking %s: %w", gitDir, err)
	}

	oldCommit, err := headCommit(ctx, dest)
	if err != nil {
		return Result{}, err
	}
	if err := g.update(ctx, dest, repoURL); err != nil {
		return Result{}, err
	}
	return summarize(ctx, dest, false, oldCommit)
}

func summarize(ctx context.Context, dest string, cloned bool, oldCommit string) (Result, error) {
	files, err := glsa.FindFiles(dest)
	if err != nil {
		return Result{}, fmt.Errorf("glsasync: counting GLSA files in %s: %w", dest, err)
	}
	newCommit, err := headCommit(ctx, dest)
	if err != nil {
		return Result{}, err
	}
	return Result{Dest: dest, Cloned: cloned, FileCount: len(files), OldCommit: oldCommit, NewCommit: newCommit}, nil
}

// headCommit returns the commit checked out in dest, or "" if there is
// none yet.
func headCommit(ctx context.Context, dest string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", dest, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	// With --quiet, a missing commit is exit code 1 and no message.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && stderr.Len() == 0 {
		return "", nil
	}
	return "", fmt.Errorf("glsasync: reading HEAD of %s: %w", dest, withStderr(err, &stderr))
}

// redact removes a "user:password@" part from repoURL before it is shown.
// It works on the raw string because url.Parse rejects some valid git
// URLs, such as passwords containing "%" or "/" and "user@host:path".
func redact(repoURL string) string {
	prefix, rest := "", repoURL
	if scheme, afterScheme, ok := strings.Cut(repoURL, "://"); ok {
		prefix, rest = scheme+"://", afterScheme
	}
	// Without a scheme ("user@host:path"), only the part before the first
	// "/" can hold credentials.
	credentialsArea := rest
	if prefix == "" {
		credentialsArea, _, _ = strings.Cut(rest, "/")
	}
	at := strings.LastIndexByte(credentialsArea, '@')
	if at < 0 {
		return repoURL
	}
	return prefix + rest[at+1:]
}

// git runs git commands and reports what it does to progress.
type git struct {
	progress io.Writer
}

func (g git) clone(ctx context.Context, dest, repoURL string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("glsasync: creating parent of %s: %w", dest, err)
	}
	g.step("Cloning %s into %s...", redact(repoURL), dest)
	if err := g.runNetwork(ctx, "", "clone", "--depth", "1", repoURL, dest); err != nil {
		return fmt.Errorf("glsasync: cloning %s into %s: %w", redact(repoURL), dest, err)
	}
	return nil
}

// update makes dest exactly match the latest upstream commit. It fetches
// and resets instead of pulling, since a read-only mirror never needs a
// merge. Setting the origin URL first makes a changed --repo take effect.
func (g git) update(ctx context.Context, dest, repoURL string) error {
	if err := g.run(ctx, dest, "remote", "set-url", "origin", repoURL); err != nil {
		return fmt.Errorf("glsasync: pointing origin at %s in %s: %w", redact(repoURL), dest, err)
	}
	g.step("Fetching updates from %s into %s...", redact(repoURL), dest)
	if err := g.runNetwork(ctx, dest, "fetch", "--depth", "1", "origin", "HEAD"); err != nil {
		return fmt.Errorf("glsasync: fetching updates in %s: %w", dest, err)
	}
	if err := g.run(ctx, dest, "reset", "--hard", "FETCH_HEAD"); err != nil {
		return fmt.Errorf("glsasync: updating %s to upstream HEAD: %w", dest, err)
	}
	return nil
}

func (g git) step(format string, args ...any) {
	if g.progress != nil {
		_, _ = fmt.Fprintf(g.progress, format+"\n", args...)
	}
}

func (g git) progressIsTerminal() bool {
	file, ok := g.progress.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

// networkArgs adds --progress after the git subcommand when progress is a
// terminal, because git hides its progress meter when stderr is a pipe.
func (g git) networkArgs(args ...string) []string {
	if g.progressIsTerminal() {
		return append([]string{args[0], "--progress"}, args[1:]...)
	}
	return args
}

// runNetwork runs a git command that downloads data, showing git's
// progress meter on a terminal.
func (g git) runNetwork(ctx context.Context, dir string, args ...string) error {
	var showOutput io.Writer
	if g.progressIsTerminal() {
		showOutput = g.progress
	}
	return runGit(ctx, dir, showOutput, g.networkArgs(args...)...)
}

func (g git) run(ctx context.Context, dir string, args ...string) error {
	return runGit(ctx, dir, nil, args...)
}

// runGit runs git in dir (the current directory if empty). Git's error
// output is added to the returned error, and also copied to showOutput if
// that is not nil.
func runGit(ctx context.Context, dir string, showOutput io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if showOutput != nil {
		cmd.Stderr = io.MultiWriter(&stderr, showOutput)
	}
	if err := cmd.Run(); err != nil {
		return withStderr(err, &stderr)
	}
	return nil
}

func withStderr(err error, stderr *bytes.Buffer) error {
	if message := strings.TrimSpace(stderr.String()); message != "" {
		return fmt.Errorf("%w: %s", err, message)
	}
	return err
}
