package glsa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	format "github.com/go-git/go-git/v5/plumbing/format/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"golang.org/x/term"
)

// DefaultRepoURL is Gentoo's GLSA repository, the same data Flatcar's
// scripts repository mirrors.
const DefaultRepoURL = "https://anongit.gentoo.org/git/data/glsa.git"

// DefaultTimeout is how long Sync may take when the caller's context has
// no deadline, so a network problem fails instead of hanging.
const DefaultTimeout = 5 * time.Minute

// fetchedHead is where an update stores the upstream HEAD it fetched. git
// itself never writes this name; "git clone" makes refs/remotes/origin/HEAD
// a symbolic ref, which go-git refuses to overwrite.
const fetchedHead = plumbing.ReferenceName("refs/flatcar-vex/upstream")

// SyncResult describes what Sync did.
type SyncResult struct {
	Dest      string
	Cloned    bool // true for a new clone, false for an update
	FileCount int  // glsa-*.xml files in Dest after syncing
	// OldCommit is the commit before an update; empty after a clone, or if
	// the existing checkout had no commit (e.g. an interrupted clone).
	OldCommit string
	NewCommit string
}

// Sync clones repoURL (DefaultRepoURL if empty) into dest, or, if dest is
// already a clone, updates it to the latest upstream commit. It uses a
// built-in git implementation, so no git binary is needed for a remote
// repoURL (a local path still uses git's upload-pack), and the result
// records exactly which upstream commit the advisories come from.
//
// Updating makes dest match upstream exactly, removing local edits and
// stray files (and saying how many), so dest should be a dedicated mirror.
// A non-empty directory that is not a clone is left untouched.
//
// If progress is not nil, Sync reports each step to it, plus a download
// progress meter if progress is a terminal.
func Sync(ctx context.Context, dest, repoURL string, progress io.Writer) (SyncResult, error) {
	if strings.TrimSpace(dest) == "" {
		return SyncResult{}, errors.New("glsa sync: dest must not be empty")
	}
	if repoURL == "" {
		repoURL = DefaultRepoURL
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}

	s := syncer{dest: dest, repoURL: repoURL, progress: progress}
	_, err := os.Stat(filepath.Join(dest, ".git"))
	switch {
	case os.IsNotExist(err):
		repo, err := s.clone(ctx)
		if err != nil {
			return SyncResult{}, err
		}
		return s.summarize(repo, true, "")
	case err != nil:
		return SyncResult{}, fmt.Errorf("glsa sync: checking %s: %w", dest, err)
	}

	repo, err := git.PlainOpen(dest)
	if err != nil {
		return SyncResult{}, fmt.Errorf("glsa sync: opening %s: %w", dest, err)
	}
	oldCommit, err := headCommit(repo)
	if err != nil {
		return SyncResult{}, fmt.Errorf("glsa sync: reading HEAD of %s: %w", dest, err)
	}
	if err := s.update(ctx, repo); err != nil {
		return SyncResult{}, err
	}
	return s.summarize(repo, false, oldCommit)
}

// syncer holds what one Sync call works on.
type syncer struct {
	dest, repoURL string
	progress      io.Writer
}

func (s syncer) clone(ctx context.Context) (*git.Repository, error) {
	if err := os.MkdirAll(filepath.Dir(s.dest), 0o755); err != nil {
		return nil, fmt.Errorf("glsa sync: creating parent of %s: %w", s.dest, err)
	}
	if entries, err := os.ReadDir(s.dest); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("glsa sync: %s is not empty and not a git clone; choose an empty or new directory", s.dest)
	}
	s.step("Cloning %s into %s...", s.repoURL, s.dest)
	repo, err := git.PlainCloneContext(ctx, s.dest, false, &git.CloneOptions{
		URL:          s.repoURL,
		Depth:        1,
		SingleBranch: true,
		Progress:     s.terminal(),
	})
	if err != nil {
		return nil, s.fail("cloning into "+s.dest, err)
	}
	return repo, nil
}

// update makes dest exactly match the latest upstream commit. It fetches
// and resets instead of pulling, since a read-only mirror never needs a
// merge. Pointing origin at the URL makes a changed --repo take effect.
func (s syncer) update(ctx context.Context, repo *git.Repository) error {
	if err := setOrigin(repo, s.repoURL); err != nil {
		return s.fail("pointing origin at the repository in "+s.dest, err)
	}
	changes, err := countLocalChanges(repo)
	if err != nil {
		return s.fail("checking for local changes in "+s.dest, err)
	}
	if changes > 0 {
		s.step("Discarding %d local change(s) in %s...", changes, s.dest)
	}

	s.step("Fetching updates from %s into %s...", s.repoURL, s.dest)
	err = repo.FetchContext(ctx, &git.FetchOptions{
		RemoteName: "origin",
		RemoteURL:  s.repoURL, // not origin's URL, which rewrite rules may change
		RefSpecs:   []config.RefSpec{config.RefSpec("+HEAD:" + fetchedHead)},
		Depth:      1,
		Force:      true,
		Progress:   s.terminal(),
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return s.fail("fetching updates in "+s.dest, err)
	}

	upstream, err := repo.Reference(fetchedHead, true)
	if err != nil {
		return s.fail("finding the fetched commit in "+s.dest, err)
	}
	restoreBranch, err := pointBranchAt(repo, upstream.Hash())
	if err != nil {
		return s.fail("updating the branch in "+s.dest, err)
	}
	if err := resetToCommit(ctx, repo, upstream.Hash()); err != nil {
		// Keep HEAD naming the commit whose files are still on disk.
		return s.fail("updating "+s.dest+" to upstream HEAD", errors.Join(err, restoreBranch()))
	}
	return nil
}

func (s syncer) summarize(repo *git.Repository, cloned bool, oldCommit string) (SyncResult, error) {
	files, err := FindFiles(s.dest)
	if err != nil {
		return SyncResult{}, fmt.Errorf("glsa sync: counting GLSA files in %s: %w", s.dest, err)
	}
	newCommit, err := headCommit(repo)
	if err != nil {
		return SyncResult{}, fmt.Errorf("glsa sync: reading HEAD of %s: %w", s.dest, err)
	}
	return SyncResult{Dest: s.dest, Cloned: cloned, FileCount: len(files), OldCommit: oldCommit, NewCommit: newCommit}, nil
}

// fail wraps err from a git step with what was being done.
func (s syncer) fail(action string, err error) error {
	return fmt.Errorf("glsa sync: %s from %s: %w", action, s.repoURL, err)
}

func (s syncer) step(format string, args ...any) {
	if s.progress != nil {
		_, _ = fmt.Fprintf(s.progress, format+"\n", args...)
	}
}

// terminal returns progress if it is a terminal and nil otherwise, so the
// download meter only appears where a person is watching.
func (s syncer) terminal() io.Writer {
	if file, ok := s.progress.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		return file
	}
	return nil
}

// setOrigin points the origin remote at url, like "git remote set-url",
// keeping any other settings it has, or adds it if missing. It writes the
// config file as read, with only that line changed, because go-git's own
// SetConfig rewrites remotes: it turns a pushurl into an extra url, and
// keeps the old url when a url.*.insteadOf rule matched it.
func setOrigin(repo *git.Repository, url string) error {
	storage, ok := repo.Storer.(*filesystem.Storage)
	if !ok {
		return errors.New("the repository is not stored on disk")
	}
	cfg, err := repo.Config()
	if err != nil {
		return err
	}
	cfg.Raw.Section("remote").Subsection("origin").SetOption("url", url)
	var raw bytes.Buffer
	if err := format.NewEncoder(&raw).Encode(cfg.Raw); err != nil {
		return err
	}
	return replaceFile(filepath.Join(storage.Filesystem().Root(), "config"), raw.Bytes())
}

// replaceFile swaps in new contents for path all at once: it writes a
// temporary file next to it and renames that over path only when the
// write fully succeeded, so a full disk can't leave path half-written.
// The file keeps its permissions; a new one is readable only by its owner.
func replaceFile(path string, contents []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	_, err = tmp.Write(contents)
	if old, statErr := os.Stat(path); err == nil && statErr == nil {
		err = tmp.Chmod(old.Mode().Perm())
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}

// countLocalChanges counts the files that differ from the checked-out
// commit: edited, deleted or added, untracked ones included.
func countLocalChanges(repo *git.Repository) (int, error) {
	worktree, err := repo.Worktree()
	if err != nil {
		return 0, err
	}
	status, err := worktree.Status()
	if err != nil {
		return 0, err
	}
	changes := 0
	for _, file := range status {
		if file.Staging != git.Unmodified || file.Worktree != git.Unmodified {
			changes++
		}
	}
	return changes, nil
}

// pointBranchAt moves the checked-out branch, or a detached HEAD, to
// commit, and returns a function that moves it back. A hard reset moves
// it too, but not for a branch with no commit yet (an interrupted clone).
func pointBranchAt(repo *git.Repository, commit plumbing.Hash) (restore func() error, err error) {
	head, err := repo.Storer.Reference(plumbing.HEAD)
	if err != nil {
		return nil, err
	}
	name := plumbing.HEAD
	if head.Type() == plumbing.SymbolicReference {
		name = head.Target()
	}
	restore = func() error { return repo.Storer.RemoveReference(name) }
	if previous, err := repo.Storer.Reference(name); err == nil {
		restore = func() error { return repo.Storer.SetReference(previous) }
	}
	return restore, repo.Storer.SetReference(plumbing.NewHashReference(name, commit))
}

// resetToCommit makes the checkout exactly match commit: changed files are
// restored and every file upstream does not have is removed, untracked or
// not, so a withdrawn advisory can never linger. Because the result does
// not depend on what is on disk, a later run also repairs one that failed
// or was killed halfway.
func resetToCommit(ctx context.Context, repo *git.Repository, commit plumbing.Hash) error {
	worktree, err := repo.Worktree()
	if err != nil {
		return err
	}
	files, err := treePaths(repo, commit)
	if err != nil {
		return err
	}
	if err := makeRoomForFiles(ctx, worktree.Filesystem.Root(), files); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return worktree.Reset(&git.ResetOptions{Commit: commit, Mode: git.HardReset})
}

// makeRoomForFiles clears what blocks the files upstream now has, as git
// does: a file or symlink where a directory must be is removed (a symlink
// is never followed), and a directory where a file must be is deleted.
// go-git would fail or write through the symlink. os.Root keeps all of
// this inside root.
func makeRoomForFiles(ctx context.Context, root string, files []string) error {
	dir, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		parts := strings.Split(file, "/")
		if !isSafePath(parts) {
			return fmt.Errorf("upstream has an unsafe path %q", file)
		}
		if err := makeRoomFor(dir, parts); err != nil {
			return err
		}
	}
	return nil
}

// isSafePath rejects paths git itself would refuse to check out: empty,
// "." or ".." parts, and anything inside .git. Checking first keeps a
// crafted upstream from getting the mirror's own git data deleted.
func isSafePath(parts []string) bool {
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.EqualFold(part, ".git") {
			return false
		}
	}
	return true
}

// makeRoomFor checks the path to one file from the top down, so it never
// looks through a symlink. Problems it leaves alone surface in the reset.
func makeRoomFor(dir *os.Root, parts []string) error {
	for depth := 1; depth <= len(parts); depth++ {
		path := filepath.Join(parts[:depth]...)
		info, err := dir.Lstat(path)
		if err != nil {
			return nil // nothing here yet, so nothing in the way
		}
		isTheFile := depth == len(parts)
		switch {
		case !isTheFile && !info.IsDir():
			return dir.Remove(path)
		case isTheFile && info.IsDir():
			return dir.RemoveAll(path)
		}
	}
	return nil
}

// treePaths lists the files in commit.
func treePaths(repo *git.Repository, commit plumbing.Hash) ([]string, error) {
	commitObject, err := repo.CommitObject(commit)
	if err != nil {
		return nil, err
	}
	files, err := commitObject.Files()
	if err != nil {
		return nil, err
	}
	var paths []string
	err = files.ForEach(func(file *object.File) error {
		paths = append(paths, file.Name)
		return nil
	})
	return paths, err
}

// headCommit returns the commit checked out in repo, or "" if there is
// none yet. A HEAD that names no existing commit is an error, so a broken
// mirror is reported instead of silently replaced.
func headCommit(repo *git.Repository) (string, error) {
	head, err := repo.Head()
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if _, err := repo.CommitObject(head.Hash()); err != nil {
		return "", fmt.Errorf("HEAD %s: %w", head.Hash(), err)
	}
	return head.Hash().String(), nil
}
