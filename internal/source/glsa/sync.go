package glsa

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
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
// Updating resets the checkout like "git reset --hard", discarding edits
// to tracked files, so dest should be a dedicated mirror. A non-empty directory that is not a clone is
// left untouched.
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
	s.step("Cloning %s into %s...", redact(s.repoURL), s.dest)
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
// merge. Recreating the origin remote makes a changed --repo take effect.
func (s syncer) update(ctx context.Context, repo *git.Repository) error {
	if err := repo.DeleteRemote("origin"); err != nil && !errors.Is(err, git.ErrRemoteNotFound) {
		return s.fail("removing old origin in "+s.dest, err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{s.repoURL}}); err != nil {
		return s.fail("pointing origin at the repository in "+s.dest, err)
	}

	s.step("Fetching updates from %s into %s...", redact(s.repoURL), s.dest)
	err := repo.FetchContext(ctx, &git.FetchOptions{
		RemoteName: "origin",
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
	if err := pointBranchAt(repo, upstream.Hash()); err != nil {
		return s.fail("updating the branch in "+s.dest, err)
	}
	if err := resetTrackedFiles(repo, upstream.Hash()); err != nil {
		return s.fail("updating "+s.dest+" to upstream HEAD", err)
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

// urlCredentials matches the "user:password@" part of URLs in go-git's
// messages, which repeat the URL as "user:REDACTED@host".
var urlCredentials = regexp.MustCompile(`://[^/@\s"]+@`)

// fail wraps err from a git step, removing any credentials in repoURL
// from the message.
func (s syncer) fail(action string, err error) error {
	message := err.Error()
	if raw, safe := s.repoURL, redact(s.repoURL); raw != safe {
		message = strings.ReplaceAll(message, raw, safe)
		message = strings.ReplaceAll(message, credentials(raw), "")
	}
	message = urlCredentials.ReplaceAllString(message, "://")
	return fmt.Errorf("glsa sync: %s from %s: %s", action, redact(s.repoURL), message)
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

// pointBranchAt moves the checked-out branch to commit. A hard reset does
// this too, except for a branch with no commit yet (an interrupted clone).
func pointBranchAt(repo *git.Repository, commit plumbing.Hash) error {
	head, err := repo.Storer.Reference(plumbing.HEAD)
	if err != nil || head.Type() != plumbing.SymbolicReference {
		return err
	}
	return repo.Storer.SetReference(plumbing.NewHashReference(head.Target(), commit))
}

// resetTrackedFiles makes the checkout match commit, like "git reset
// --hard": tracked files are restored or removed, untracked files are kept.
// go-git's hard reset alone would also delete untracked files, so it is
// limited to the paths tracked before or after the reset.
func resetTrackedFiles(repo *git.Repository, commit plumbing.Hash) error {
	worktree, err := repo.Worktree()
	if err != nil {
		return err
	}
	trackedBefore, err := indexPaths(repo)
	if err != nil {
		return err
	}
	trackedAfter, err := treePaths(repo, commit)
	if err != nil {
		return err
	}
	if err := removeDirectoriesInTheWay(worktree.Filesystem.Root(), trackedAfter); err != nil {
		return err
	}
	tracked := slices.Concat(trackedBefore, trackedAfter)
	if len(tracked) == 0 {
		return nil // go-git reads an empty list as "every file"
	}
	return worktree.Reset(&git.ResetOptions{Commit: commit, Mode: git.HardReset, Files: tracked})
}

// removeDirectoriesInTheWay deletes directories where a file must go, as
// git does when upstream turns a directory into a file; go-git would fail.
// os.Root keeps every path inside root, even through symlinks a hostile
// upstream may have checked out earlier.
func removeDirectoriesInTheWay(root string, files []string) error {
	dir, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	for _, file := range files {
		name := filepath.FromSlash(file)
		if info, err := dir.Lstat(name); err == nil && info.IsDir() {
			if err := dir.RemoveAll(name); err != nil {
				return err
			}
		}
	}
	return nil
}

// indexPaths lists the files repo's index tracks.
func indexPaths(repo *git.Repository) ([]string, error) {
	idx, err := repo.Storer.Index()
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(idx.Entries))
	for _, entry := range idx.Entries {
		paths = append(paths, entry.Name)
	}
	return paths, nil
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

// redact removes a "user:password@" part from repoURL before it is shown.
// It works on the raw string because url.Parse rejects some valid git
// URLs, such as passwords containing "%" or "/" and "user@host:path".
func redact(repoURL string) string {
	return strings.Replace(repoURL, credentials(repoURL), "", 1)
}

// credentials returns the "user:password@" part of repoURL, or "".
func credentials(repoURL string) string {
	rest := repoURL
	if _, afterScheme, ok := strings.Cut(repoURL, "://"); ok {
		rest = afterScheme
	}
	// Only the part before the first "/" can hold credentials, except with
	// a scheme, where the password itself may contain "/".
	credentialsArea := rest
	if !strings.Contains(repoURL, "://") {
		credentialsArea, _, _ = strings.Cut(rest, "/")
	}
	at := strings.LastIndexByte(credentialsArea, '@')
	if at < 0 {
		return ""
	}
	return rest[:at+1]
}
