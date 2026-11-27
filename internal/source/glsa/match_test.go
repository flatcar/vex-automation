package glsa

import (
	"testing"

	"github.com/flatcar/vex-automation/internal/sbom"
	"github.com/flatcar/vex-automation/internal/vuln"
)

func fuseGLSA() GLSA {
	return GLSA{
		ID:   "202604-03",
		CVEs: []string{"CVE-2026-33150", "CVE-2026-33179"},
		Packages: []AffectedPackage{
			{
				CategoryName: "sys-fs/fuse",
				Arch:         "*",
				Unaffected:   []VersionRange{{Op: "ge", Version: "3.18.1"}},
				Vulnerable:   []VersionRange{{Op: "lt", Version: "3.18.1"}},
			},
		},
	}
}

func TestRunAffected(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Ebuild, Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
	}

	findings := Match(pkgs, []GLSA{fuseGLSA()}, "amd64")

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per CVE): %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Status != vuln.StatusAffected {
			t.Errorf("finding %+v: want vuln.Status=affected for version below the unaffected range", f)
		}
		if f.Source != vuln.SourceGLSA {
			t.Errorf("Source = %q, want %q", f.Source, vuln.SourceGLSA)
		}
		if f.RefID != "202604-03" {
			t.Errorf("RefID = %q, want 202604-03", f.RefID)
		}
	}
	// Sorted by CVE.
	if findings[0].CVE != "CVE-2026-33150" || findings[1].CVE != "CVE-2026-33179" {
		t.Errorf("findings not sorted by CVE: %+v", findings)
	}
}

func TestRunFixed(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Ebuild, Category: "sys-fs", Name: "fuse", Version: "3.18.1", PURL: "pkg:ebuild/sys-fs/fuse@3.18.1"},
	}

	findings := Match(pkgs, []GLSA{fuseGLSA()}, "amd64")

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.Status != vuln.StatusFixed {
			t.Errorf("finding %+v: want vuln.Status=fixed for version at the unaffected boundary", f)
		}
	}
}

func TestRunNoMatchingPackage(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Ebuild, Category: "sys-apps", Name: "systemd", Version: "255.4-r2", PURL: "pkg:ebuild/sys-apps/systemd@255.4-r2"},
	}

	findings := Match(pkgs, []GLSA{fuseGLSA()}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 for an unrelated package", len(findings))
	}
}

func TestRunArchMismatch(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Ebuild, Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
	}
	g := fuseGLSA()
	g.Packages[0].Arch = "arm64"

	findings := Match(pkgs, []GLSA{g}, "amd64")
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 when GLSA arch doesn't match", len(findings))
	}
}

// An unparseable installed version must not make the vulnerability vanish
// from the VEX document: it is reported as under investigation.
func TestRunUnparseableVersionIsUnderInvestigation(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Ebuild, Category: "sys-fs", Name: "fuse", Version: "not-a-version!!", PURL: "pkg:ebuild/sys-fs/fuse@bogus"},
	}

	findings := Match(pkgs, []GLSA{fuseGLSA()}, "amd64")
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Status != vuln.StatusUnderInvestigation || f.Note == "" {
			t.Errorf("finding %+v: want vuln.Status=under_investigation with a note", f)
		}
	}
}

func TestMatchWithNoCVEsUsesGLSAID(t *testing.T) {
	pkgs := []sbom.Package{
		{Ecosystem: sbom.Ebuild, Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
	}
	g := fuseGLSA()
	g.CVEs = nil

	findings := Match(pkgs, []GLSA{g}, "amd64")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 for a GLSA with no CVE references: %+v", len(findings), findings)
	}
	if findings[0].CVE != "GLSA-202604-03" || findings[0].Status != vuln.StatusAffected {
		t.Errorf("finding = %+v, want CVE=GLSA-202604-03 vuln.Status=affected", findings[0])
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		vulnerable []VersionRange
		unaffected []VersionRange
		want       vuln.Status
	}{
		{
			// Regression: the vulnerable range also covers fixed revisions
			// of an older branch. Installed 1.5 is not >=~1.0-r1 (different
			// base version), so it is affected, not fixed.
			name:       "revision op only covers its own base version",
			version:    "1.5",
			vulnerable: []VersionRange{{Op: "lt", Version: "2.0"}},
			unaffected: []VersionRange{{Op: "ge", Version: "2.0"}, {Op: "rge", Version: "1.0-r1"}},
			want:       vuln.StatusAffected,
		},
		{
			name:       "revision op matches a fixed revision",
			version:    "1.0-r2",
			vulnerable: []VersionRange{{Op: "lt", Version: "2.0"}},
			unaffected: []VersionRange{{Op: "ge", Version: "2.0"}, {Op: "rge", Version: "1.0-r1"}},
			want:       vuln.StatusFixed,
		},
		{
			name:       "outside every range is not affected",
			version:    "1.3",
			vulnerable: []VersionRange{{Op: "eq", Version: "1.2*"}},
			unaffected: []VersionRange{{Op: "ge", Version: "1.4"}},
			want:       vuln.StatusNotAffected,
		},
		{
			// Regression: a numeric slot is matched against the installed
			// version's branch, so 3.12.1 is checked against the 3.12
			// ranges only and the 3.11 "ge 3.11.9" range doesn't fix it.
			name:    "numeric slots select the matching branch",
			version: "3.12.1",
			vulnerable: []VersionRange{
				{Op: "lt", Version: "3.11.9", Slot: "3.11"},
				{Op: "lt", Version: "3.12.4", Slot: "3.12"},
			},
			unaffected: []VersionRange{
				{Op: "ge", Version: "3.11.9", Slot: "3.11"},
				{Op: "ge", Version: "3.12.4", Slot: "3.12"},
			},
			want: vuln.StatusAffected,
		},
		{
			name:       "numeric slot prefix must end at a component boundary",
			version:    "17.0.1",
			vulnerable: []VersionRange{{Op: "lt", Version: "17.0.2", Slot: "17"}},
			// Would make 17.0.1 fixed if slot "1" were taken as its branch.
			unaffected: []VersionRange{{Op: "ge", Version: "17.0.0", Slot: "1"}},
			want:       vuln.StatusAffected,
		},
		{
			// Regression: webkit-gtk uses slots "4"/"6" for 2.x versions,
			// so a numeric slot that isn't the installed branch must not be
			// silently ruled out.
			name:       "numeric slots that don't follow the version are unknown",
			version:    "2.44.0",
			vulnerable: []VersionRange{{Op: "lt", Version: "2.44.2", Slot: "4"}},
			unaffected: []VersionRange{{Op: "ge", Version: "2.44.2", Slot: "4"}},
			want:       vuln.StatusUnderInvestigation,
		},
		{
			// Regression: a fix in an unknown slot doesn't show the
			// installed version is fixed; in another slot it is not affected.
			name:       "newer than a fix in an unknown slot",
			version:    "2.45.0",
			vulnerable: []VersionRange{{Op: "lt", Version: "2.44.2", Slot: "4"}},
			unaffected: []VersionRange{{Op: "ge", Version: "2.44.2", Slot: "4"}},
			want:       vuln.StatusUnderInvestigation,
		},
		{
			name:       "newer than a revision-restricted fix in an unknown slot",
			version:    "2.45.0",
			vulnerable: []VersionRange{{Op: "lt", Version: "2.44.2", Slot: "4"}},
			unaffected: []VersionRange{{Op: "rge", Version: "2.44.2", Slot: "4"}},
			want:       vuln.StatusUnderInvestigation,
		},
		{
			name:       "fix in an applicable range outweighs one in an unknown slot",
			version:    "2.45.0",
			vulnerable: []VersionRange{{Op: "lt", Version: "2.44.2"}},
			unaffected: []VersionRange{{Op: "ge", Version: "2.44.2", Slot: "4"}, {Op: "rge", Version: "2.44.2"}},
			want:       vuln.StatusFixed,
		},
		{
			name:    "other branch's slot is ruled out when the installed branch is listed",
			version: "3.12.5",
			// The 3.11 range would match 3.12.5 if its slot were ignored.
			vulnerable: []VersionRange{{Op: "lt", Version: "3.13", Slot: "3.11"}, {Op: "lt", Version: "3.12.4", Slot: "3.12"}},
			want:       vuln.StatusNotAffected,
		},
		{
			name:       "named slot that could change the answer",
			version:    "115.0",
			vulnerable: []VersionRange{{Op: "lt", Version: "115.9", Slot: "esr"}},
			unaffected: []VersionRange{{Op: "ge", Version: "115.9", Slot: "esr"}},
			want:       vuln.StatusUnderInvestigation,
		},
		{
			name:       "named slot that could change the answer next to an unslotted range",
			version:    "120.0",
			vulnerable: []VersionRange{{Op: "lt", Version: "125.0", Slot: "esr"}},
			unaffected: []VersionRange{{Op: "ge", Version: "130.0"}},
			want:       vuln.StatusUnderInvestigation,
		},
		{
			name:       "named slot range that doesn't match is irrelevant",
			version:    "120.0",
			vulnerable: []VersionRange{{Op: "lt", Version: "110.0"}, {Op: "lt", Version: "115.9", Slot: "esr"}},
			unaffected: []VersionRange{{Op: "ge", Version: "130.0"}},
			want:       vuln.StatusNotAffected,
		},
		{
			// Regression: a newer branch than every rge fix matches no
			// range, and was reported as never having had the vulnerable
			// code (GLSA 202003-52 vs samba 4.22.5).
			name:       "newer than a revision-restricted fix",
			version:    "4.22.5-r1",
			vulnerable: []VersionRange{{Op: "lt", Version: "4.11.6"}},
			unaffected: []VersionRange{
				{Op: "rge", Version: "4.9.18"},
				{Op: "rge", Version: "4.11.6"},
			},
			want: vuln.StatusFixed,
		},
		{
			name:       "older than every vulnerable range",
			version:    "1.0",
			vulnerable: []VersionRange{{Op: "rlt", Version: "2.0-r3"}},
			unaffected: []VersionRange{{Op: "rge", Version: "2.0-r3"}},
			want:       vuln.StatusNotAffected,
		},
		{
			name:       "glob range",
			version:    "2.4.7-r1",
			vulnerable: []VersionRange{{Op: "eq", Version: "2.4*"}},
			want:       vuln.StatusAffected,
		},
		{
			name:       "unknown operator",
			version:    "1.0",
			vulnerable: []VersionRange{{Op: "bogus", Version: "2.0"}},
			want:       vuln.StatusUnderInvestigation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, note := evaluate(tt.version, AffectedPackage{Vulnerable: tt.vulnerable, Unaffected: tt.unaffected})
			if got != tt.want {
				t.Errorf("evaluate(%q) = %q (%s), want %q", tt.version, got, note, tt.want)
			}
			if got == vuln.StatusUnderInvestigation && note == "" {
				t.Error("under_investigation result has no note")
			}
		})
	}
}

// Advisory entries may share one backing array. Evaluating one entry must
// not overwrite another entry's ranges.
func TestEvaluateDoesNotModifyAdvisoryRanges(t *testing.T) {
	shared := make([]VersionRange, 2, 3)
	shared[0] = VersionRange{Op: "lt", Version: "2.0"}
	shared[1] = VersionRange{Op: "lt", Version: "5.0"}
	other := shared[1]
	affected := AffectedPackage{
		Vulnerable: shared[:1],
		Unaffected: []VersionRange{{Op: "ge", Version: "2.0"}},
	}

	evaluate("1.0", affected)

	if shared[1] != other {
		t.Errorf("evaluate overwrote a shared range: got %+v, want %+v", shared[1], other)
	}
}
