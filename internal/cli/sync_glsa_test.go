package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// newTestGLSAUpstream creates a throwaway local Git repository containing a
// single glsa-*.xml file, standing in for the real anongit.gentoo.org
// remote so this test stays offline.
func newTestGLSAUpstream(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
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

func TestSyncGLSACmdClonesAndReportsCount(t *testing.T) {
	upstream := newTestGLSAUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"sync-glsa", "--dest", dest, "--repo", upstream})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v\noutput: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "Cloned") {
		t.Errorf("expected output to mention a clone, got: %q", out.String())
	}
	if !strings.Contains(out.String(), "1 advisories") {
		t.Errorf("expected output to report 1 advisory, got: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(dest, "glsa-202601-01.xml")); err != nil {
		t.Errorf("expected synced file to be present: %v", err)
	}
}

func TestSyncGLSACmdRejectsEmptyRepoDest(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"sync-glsa", "--dest", "", "--repo", "https://example.invalid/glsa.git"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for an empty --dest, got nil")
	}
}

func TestSyncGLSACmdHelp(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"sync-glsa", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	for _, want := range []string{"--dest", "--repo", "--timeout"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help output missing %q: %q", want, out.String())
		}
	}
}

func TestSyncGLSACmdReportsProgressAndChanges(t *testing.T) {
	upstream := newTestGLSAUpstream(t)
	dest := filepath.Join(t.TempDir(), "glsa-mirror")

	run := func() (string, string) {
		t.Helper()
		cmd := NewRootCmd()
		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetArgs([]string{"sync-glsa", "--dest", dest, "--repo", upstream})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute: %v\nstderr: %s", err, stderr.String())
		}
		return stdout.String(), stderr.String()
	}

	if _, stderr := run(); !strings.Contains(stderr, "Cloning "+upstream) {
		t.Errorf("clone stderr = %q, want a Cloning step", stderr)
	}

	stdout, stderr := run()
	if !strings.Contains(stderr, "Fetching updates from "+upstream) {
		t.Errorf("update stderr = %q, want a Fetching step", stderr)
	}
	if want := "GLSA mirror at " + dest + " is already up to date (1 advisories)"; !strings.Contains(stdout, want) {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}

	cmd := exec.Command("git", "commit", "--allow-empty", "-m", "next")
	cmd.Dir = upstream
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
	if stdout, _ := run(); !regexp.MustCompile(`Updated GLSA mirror at .* \(1 advisories, [0-9a-f]{12} -> [0-9a-f]{12}\)`).MatchString(stdout) {
		t.Errorf("stdout = %q, want old and new commit", stdout)
	}
}
