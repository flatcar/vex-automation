package match

import (
	"testing"

	"github.com/flatcar/vex-automation/internal/glsa"
	"github.com/flatcar/vex-automation/internal/sbom"
)

func fuseGLSA() glsa.GLSA {
	return glsa.GLSA{
		ID:   "202604-03",
		CVEs: []string{"CVE-2026-33150", "CVE-2026-33179"},
		Packages: []glsa.AffectedPackage{
			{
				CategoryName: "sys-fs/fuse",
				Arch:         "*",
				Unaffected:   []glsa.VersionRange{{Op: "ge", Version: "3.18.1"}},
				Vulnerable:   []glsa.VersionRange{{Op: "lt", Version: "3.18.1"}},
			},
		},
	}
}

func TestRunAffected(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
	}

	findings := Run(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per CVE): %+v", len(findings), findings)
	}
	for _, f := range findings {
		if !f.Affected {
			t.Errorf("finding %+v: want Affected=true for version below the unaffected range", f)
		}
		if f.GLSAID != "202604-03" {
			t.Errorf("GLSAID = %q, want 202604-03", f.GLSAID)
		}
	}
	// Sorted by CVE.
	if findings[0].CVE != "CVE-2026-33150" || findings[1].CVE != "CVE-2026-33179" {
		t.Errorf("findings not sorted by CVE: %+v", findings)
	}
}

func TestRunFixed(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "3.18.1", PURL: "pkg:ebuild/sys-fs/fuse@3.18.1"},
	}

	findings := Run(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.Affected {
			t.Errorf("finding %+v: want Affected=false for version at the unaffected boundary", f)
		}
	}
}

func TestRunNoMatchingPackage(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-apps", Name: "systemd", Version: "255.4-r2", PURL: "pkg:ebuild/sys-apps/systemd@255.4-r2"},
	}

	findings := Run(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 for an unrelated package", len(findings))
	}
}

func TestRunArchMismatch(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
	}
	g := fuseGLSA()
	g.Packages[0].Arch = "arm64"

	findings := Run(pkgs, []glsa.GLSA{g}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 when GLSA arch doesn't match", len(findings))
	}
}

func TestRunSkipsUnparseableVersion(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "not-a-version!!", PURL: "pkg:ebuild/sys-fs/fuse@bogus"},
	}

	findings := Run(pkgs, []glsa.GLSA{fuseGLSA()}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 when the installed version can't be parsed", len(findings))
	}
}

func TestRunGLSAWithNoCVEsIsSkipped(t *testing.T) {
	pkgs := []sbom.Package{
		{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
	}
	g := fuseGLSA()
	g.CVEs = nil

	findings := Run(pkgs, []glsa.GLSA{g}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 for a GLSA with no CVE references", len(findings))
	}
}
