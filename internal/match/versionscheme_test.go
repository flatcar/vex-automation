package match

import (
	"testing"

	"github.com/flatcar/vex-automation/internal/glsa"
	"github.com/flatcar/vex-automation/internal/sbom"
)

// Regression: Flatcar versions ca-certificates by NSS release (3.125) and
// Gentoo by date (20260816.3.125), so every ca-certificates GLSA reported
// Flatcar's current bundle as affected (62 CVEs on stable 4593.2.4).
func TestEvaluatePackageCACertificates(t *testing.T) {
	const name = "app-misc/ca-certificates"
	// GLSA 202610-01, compromised intermediate CA.
	nssRanges := glsa.AffectedPackage{
		CategoryName: name,
		Vulnerable:   []glsa.VersionRange{{Op: "lt", Version: "20260816.3.125"}},
		Unaffected:   []glsa.VersionRange{{Op: "ge", Version: "20260816.3.125"}},
	}
	// GLSA 201412-09, a date-only bundle from 2011.
	dateRanges := glsa.AffectedPackage{
		CategoryName: name,
		Vulnerable:   []glsa.VersionRange{{Op: "lt", Version: "20110502-r1"}},
		Unaffected:   []glsa.VersionRange{{Op: "ge", Version: "20110502-r1"}},
	}
	tests := []struct {
		name    string
		version string
		ap      glsa.AffectedPackage
		want    Status
	}{
		{"NSS version with the fix", "3.125", nssRanges, StatusFixed},
		{"Flatcar revision is ignored", "3.125-r1", nssRanges, StatusFixed},
		{"older NSS version", "3.124", nssRanges, StatusAffected},
		{"newer than a pre-2014 date-only bundle", "3.125", dateRanges, StatusFixed},
		{"NSS too old to order against a date", "3.16", dateRanges, StatusUnderInvestigation},
		{"Gentoo's own scheme compares as usual", "20250101.3.110", nssRanges, StatusAffected},
		{"unknown installed scheme", "not-nss", nssRanges, StatusUnderInvestigation},
		{
			"recent date-only GLSA version can't be ordered", "3.125",
			glsa.AffectedPackage{CategoryName: name, Vulnerable: []glsa.VersionRange{{Op: "lt", Version: "20270101"}}},
			StatusUnderInvestigation,
		},
		{
			"fix is only a Gentoo revision bump", "3.125",
			glsa.AffectedPackage{
				CategoryName: name,
				Vulnerable:   []glsa.VersionRange{{Op: "lt", Version: "20260816.3.125-r1"}},
				Unaffected:   []glsa.VersionRange{{Op: "ge", Version: "20260816.3.125-r1"}},
			},
			StatusUnderInvestigation,
		},
		{
			"lt/ge pair at the installed NSS version is trusted", "3.125",
			glsa.AffectedPackage{
				CategoryName: name,
				Vulnerable:   []glsa.VersionRange{{Op: "lt", Version: "20260901.3.125"}},
				Unaffected:   []glsa.VersionRange{{Op: "ge", Version: "20260901.3.125"}},
			},
			StatusFixed,
		},
		{
			"vulnerable bundle shares the installed NSS version", "3.125",
			glsa.AffectedPackage{
				CategoryName: name,
				Vulnerable:   []glsa.VersionRange{{Op: "eq", Version: "20260816.3.125"}},
				Unaffected:   []glsa.VersionRange{{Op: "ge", Version: "20260901.3.125"}},
			},
			StatusUnderInvestigation,
		},
		{
			"boundary at the installed NSS version, no matching pair", "3.125",
			glsa.AffectedPackage{CategoryName: name, Vulnerable: []glsa.VersionRange{{Op: "lt", Version: "20260901.3.125"}}},
			StatusUnderInvestigation,
		},
		{
			"newer NSS version than a revision-bump fix", "3.126",
			glsa.AffectedPackage{
				CategoryName: name,
				Vulnerable:   []glsa.VersionRange{{Op: "lt", Version: "20260816.3.125-r1"}},
				Unaffected:   []glsa.VersionRange{{Op: "ge", Version: "20260816.3.125-r1"}},
			},
			StatusFixed,
		},
		{
			"glob range can't be translated", "3.125",
			glsa.AffectedPackage{CategoryName: name, Vulnerable: []glsa.VersionRange{{Op: "eq", Version: "20260816.3.12*"}}},
			StatusUnderInvestigation,
		},
		{
			"revision-only range can't be translated", "3.125",
			glsa.AffectedPackage{CategoryName: name, Vulnerable: []glsa.VersionRange{{Op: "rlt", Version: "20260816.3.125-r2"}}},
			StatusUnderInvestigation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, note := evaluatePackage(name, tt.version, tt.ap)
			if got != tt.want {
				t.Errorf("evaluatePackage(%q) = %q (%s), want %q", tt.version, got, note, tt.want)
			}
			if got == StatusUnderInvestigation && note == "" {
				t.Error("under_investigation result has no note")
			}
		})
	}
}

func TestEvaluatePackageWithoutExceptionIsUnchanged(t *testing.T) {
	ap := glsa.AffectedPackage{
		CategoryName: "dev-libs/foo",
		Vulnerable:   []glsa.VersionRange{{Op: "lt", Version: "20260816.3.125"}},
	}
	if got, _ := evaluatePackage("dev-libs/foo", "3.125", ap); got != StatusAffected {
		t.Errorf("got %q, want affected (no version scheme exception)", got)
	}
}

func TestRunAppliesVersionSchemeException(t *testing.T) {
	pkgs := []sbom.Package{{Category: "app-misc", Name: "ca-certificates", Version: "3.125", PURL: "pkg:ebuild/app-misc/ca-certificates@3.125"}}
	g := glsa.GLSA{
		ID:   "202610-01",
		CVEs: []string{"CVE-2026-0001"},
		Packages: []glsa.AffectedPackage{{
			CategoryName: "app-misc/ca-certificates",
			Arch:         "*",
			Vulnerable:   []glsa.VersionRange{{Op: "lt", Version: "20260816.3.125"}},
			Unaffected:   []glsa.VersionRange{{Op: "ge", Version: "20260816.3.125"}},
		}},
	}
	findings := RunGLSA(pkgs, []glsa.GLSA{g}, "amd64")
	if len(findings) != 1 || findings[0].Status != StatusFixed {
		t.Errorf("got %+v, want one fixed finding", findings)
	}
}
