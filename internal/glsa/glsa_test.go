package glsa

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleGLSA = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE glsa SYSTEM "http://www.gentoo.org/dtd/glsa.dtd">
<glsa id="202604-03">
    <title>FUSE: Multiple Vulnerabilities</title>
    <synopsis>Multiple vulnerabilities have been found in FUSE.</synopsis>
    <affected>
        <package name="sys-fs/fuse" auto="yes" arch="*">
            <unaffected range="ge" slot="3">3.18.1</unaffected>
            <vulnerable range="lt" slot="3">3.18.1</vulnerable>
        </package>
    </affected>
    <references>
        <uri link="https://nvd.nist.gov/vuln/detail/CVE-2026-33150">CVE-2026-33150</uri>
        <uri link="https://nvd.nist.gov/vuln/detail/CVE-2026-33179">CVE-2026-33179</uri>
    </references>
</glsa>`

const noCVEGLSA = `<?xml version="1.0" encoding="UTF-8"?>
<glsa id="202601-01">
    <title>Nothing to see</title>
    <affected>
        <package name="app-misc/foo" arch="*">
            <vulnerable range="lt">1.0</vulnerable>
        </package>
    </affected>
    <references></references>
</glsa>`

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "glsa-202604-03.xml", sampleGLSA)
	writeFile(t, dir, "glsa-202601-01.xml", noCVEGLSA)
	writeFile(t, dir, "not-a-glsa.txt", "ignore me")

	glsas, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir returned error: %v", err)
	}
	if len(glsas) != 2 {
		t.Fatalf("got %d GLSAs, want 2: %+v", len(glsas), glsas)
	}

	// Sorted by ID.
	if glsas[0].ID != "202601-01" || glsas[1].ID != "202604-03" {
		t.Fatalf("GLSAs not sorted by ID: %+v", glsas)
	}

	fuse := glsas[1]
	if fuse.Title != "FUSE: Multiple Vulnerabilities" {
		t.Errorf("Title = %q", fuse.Title)
	}
	wantCVEs := []string{"CVE-2026-33150", "CVE-2026-33179"}
	if len(fuse.CVEs) != len(wantCVEs) {
		t.Fatalf("CVEs = %v, want %v", fuse.CVEs, wantCVEs)
	}
	for i, c := range wantCVEs {
		if fuse.CVEs[i] != c {
			t.Errorf("CVEs[%d] = %q, want %q", i, fuse.CVEs[i], c)
		}
	}

	if len(fuse.Packages) != 1 {
		t.Fatalf("Packages = %+v, want 1 entry", fuse.Packages)
	}
	pkg := fuse.Packages[0]
	if pkg.CategoryName != "sys-fs/fuse" {
		t.Errorf("CategoryName = %q", pkg.CategoryName)
	}
	if !pkg.MatchesArch("amd64") {
		t.Error("expected arch=\"*\" package to match amd64")
	}
	if len(pkg.Vulnerable) != 1 || pkg.Vulnerable[0].Op != "lt" || pkg.Vulnerable[0].Version != "3.18.1" {
		t.Errorf("Vulnerable = %+v", pkg.Vulnerable)
	}
	if len(pkg.Unaffected) != 1 || pkg.Unaffected[0].Op != "ge" || pkg.Unaffected[0].Version != "3.18.1" {
		t.Errorf("Unaffected = %+v", pkg.Unaffected)
	}

	// GLSA with an empty <references> block (no CVEs) should still load.
	empty := glsas[0]
	if len(empty.CVEs) != 0 {
		t.Errorf("expected no CVEs, got %v", empty.CVEs)
	}
}

func TestLoadDirNoFiles(t *testing.T) {
	if _, err := LoadDir(t.TempDir()); err == nil {
		t.Error("expected error for directory with no glsa-*.xml files, got nil")
	}
}

func TestLoadDirMissingDir(t *testing.T) {
	if _, err := LoadDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("expected error for missing directory, got nil")
	}
}

func TestLoadDirRecursesSubdirectories(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "202604")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, sub, "glsa-202604-03.xml", sampleGLSA)

	glsas, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir returned error: %v", err)
	}
	if len(glsas) != 1 {
		t.Fatalf("got %d GLSAs, want 1", len(glsas))
	}
}

// TestLoadDirIgnoresNonMatchingFilenames ensures the "glsa-*.xml" filter is
// exact, not just "*.xml with glsa somewhere in the name": unrelated or
// oddly-named XML files sitting in the same directory (as could plausibly
// happen in a hand-maintained or third-party directory) must not be parsed.
func TestLoadDirIgnoresNonMatchingFilenames(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "glsa-202604-03.xml", sampleGLSA)
	writeFile(t, dir, "not-glsa.xml", "<not-a-glsa/>")
	writeFile(t, dir, "myglsa.xml", "<not-a-glsa-either/>")
	writeFile(t, dir, "glsa-202604-03.xml.bak", sampleGLSA)

	glsas, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir returned error: %v", err)
	}
	if len(glsas) != 1 {
		t.Fatalf("got %d GLSAs, want 1 (only the correctly-named file)", len(glsas))
	}
}

// TestLoadDirSkipsGitDirectory ensures a directory synced via
// internal/glsasync (which contains a .git checkout alongside the *.xml
// advisories) doesn't have LoadDir needlessly descend into .git's internals.
func TestLoadDirSkipsGitDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "glsa-202604-03.xml", sampleGLSA)

	gitDir := filepath.Join(dir, ".git", "objects", "pack")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A file that would (incorrectly) match the old "*.xml containing glsa"
	// filter if .git were still walked into.
	writeFile(t, gitDir, "glsa-fake.xml", "<not-a-real-glsa/>")

	glsas, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir returned error: %v", err)
	}
	if len(glsas) != 1 {
		t.Fatalf("got %d GLSAs, want 1 (the .git directory should have been skipped)", len(glsas))
	}
}

func TestMatchesArch(t *testing.T) {
	cases := []struct {
		arch string
		want bool
	}{
		{"", true},
		{"*", true},
		{"amd64 x86", true},
		{"~amd64", true},
		{"x86", false},
	}
	for _, tc := range cases {
		p := AffectedPackage{Arch: tc.arch}
		if got := p.MatchesArch("amd64"); got != tc.want {
			t.Errorf("MatchesArch(%q) against amd64 = %v, want %v", tc.arch, got, tc.want)
		}
	}
}
