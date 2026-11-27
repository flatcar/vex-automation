package glsa

import (
	"testing"

	"github.com/flatcar/vex-automation/internal/sbom"
	"github.com/flatcar/vex-automation/internal/vuln"
)

// Regression: Flatcar versions ca-certificates by NSS release (3.125) and
// Gentoo by date (20260816.3.125), so every ca-certificates GLSA reported
// Flatcar's current bundle as affected (62 CVEs on stable 4593.2.4).
func TestEvaluatePackageCACertificates(t *testing.T) {
	const name = "app-misc/ca-certificates"
	// GLSA 202610-01, compromised intermediate CA.
	nssRanges := AffectedPackage{
		CategoryName: name,
		Vulnerable:   []VersionRange{{Op: "lt", Version: "20260816.3.125"}},
		Unaffected:   []VersionRange{{Op: "ge", Version: "20260816.3.125"}},
	}
	// GLSA 201412-09, a date-only bundle from 2011.
	dateRanges := AffectedPackage{
		CategoryName: name,
		Vulnerable:   []VersionRange{{Op: "lt", Version: "20110502-r1"}},
		Unaffected:   []VersionRange{{Op: "ge", Version: "20110502-r1"}},
	}
	tests := []struct {
		name    string
		version string
		ap      AffectedPackage
		want    vuln.Status
	}{
		{"NSS version with the fix", "3.125", nssRanges, vuln.StatusFixed},
		{"Flatcar revision is ignored", "3.125-r1", nssRanges, vuln.StatusFixed},
		{"older NSS version", "3.124", nssRanges, vuln.StatusAffected},
		{"newer than a pre-2014 date-only bundle", "3.125", dateRanges, vuln.StatusFixed},
		{"NSS too old to order against a date", "3.16", dateRanges, vuln.StatusUnderInvestigation},
		{"Gentoo's own scheme compares as usual", "20250101.3.110", nssRanges, vuln.StatusAffected},
		{"unknown installed scheme", "not-nss", nssRanges, vuln.StatusUnderInvestigation},
		{
			"recent date-only GLSA version can't be ordered", "3.125",
			AffectedPackage{CategoryName: name, Vulnerable: []VersionRange{{Op: "lt", Version: "20270101"}}},
			vuln.StatusUnderInvestigation,
		},
		{
			"fix is only a Gentoo revision bump", "3.125",
			AffectedPackage{
				CategoryName: name,
				Vulnerable:   []VersionRange{{Op: "lt", Version: "20260816.3.125-r1"}},
				Unaffected:   []VersionRange{{Op: "ge", Version: "20260816.3.125-r1"}},
			},
			vuln.StatusUnderInvestigation,
		},
		{
			"lt/ge pair at the installed NSS version is trusted", "3.125",
			AffectedPackage{
				CategoryName: name,
				Vulnerable:   []VersionRange{{Op: "lt", Version: "20260901.3.125"}},
				Unaffected:   []VersionRange{{Op: "ge", Version: "20260901.3.125"}},
			},
			vuln.StatusFixed,
		},
		{
			"vulnerable bundle shares the installed NSS version", "3.125",
			AffectedPackage{
				CategoryName: name,
				Vulnerable:   []VersionRange{{Op: "eq", Version: "20260816.3.125"}},
				Unaffected:   []VersionRange{{Op: "ge", Version: "20260901.3.125"}},
			},
			vuln.StatusUnderInvestigation,
		},
		{
			"boundary at the installed NSS version, no matching pair", "3.125",
			AffectedPackage{CategoryName: name, Vulnerable: []VersionRange{{Op: "lt", Version: "20260901.3.125"}}},
			vuln.StatusUnderInvestigation,
		},
		{
			"newer NSS version than a revision-bump fix", "3.126",
			AffectedPackage{
				CategoryName: name,
				Vulnerable:   []VersionRange{{Op: "lt", Version: "20260816.3.125-r1"}},
				Unaffected:   []VersionRange{{Op: "ge", Version: "20260816.3.125-r1"}},
			},
			vuln.StatusFixed,
		},
		{
			"glob range can't be translated", "3.125",
			AffectedPackage{CategoryName: name, Vulnerable: []VersionRange{{Op: "eq", Version: "20260816.3.12*"}}},
			vuln.StatusUnderInvestigation,
		},
		{
			"revision-only range can't be translated", "3.125",
			AffectedPackage{CategoryName: name, Vulnerable: []VersionRange{{Op: "rlt", Version: "20260816.3.125-r2"}}},
			vuln.StatusUnderInvestigation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, note := evaluatePackage(name, tt.version, tt.ap)
			if got != tt.want {
				t.Errorf("evaluatePackage(%q) = %q (%s), want %q", tt.version, got, note, tt.want)
			}
			if got == vuln.StatusUnderInvestigation && note == "" {
				t.Error("under_investigation result has no note")
			}
		})
	}
}

func TestEvaluatePackageWithoutExceptionIsUnchanged(t *testing.T) {
	ap := AffectedPackage{
		CategoryName: "dev-libs/foo",
		Vulnerable:   []VersionRange{{Op: "lt", Version: "20260816.3.125"}},
	}
	if got, _ := evaluatePackage("dev-libs/foo", "3.125", ap); got != vuln.StatusAffected {
		t.Errorf("got %q, want affected (no version scheme exception)", got)
	}
}

func TestRunAppliesVersionSchemeException(t *testing.T) {
	pkgs := []sbom.Package{{Ecosystem: sbom.Ebuild, Category: "app-misc", Name: "ca-certificates", Version: "3.125", PURL: "pkg:ebuild/app-misc/ca-certificates@3.125"}}
	g := GLSA{
		ID:   "202610-01",
		CVEs: []string{"CVE-2026-0001"},
		Packages: []AffectedPackage{{
			CategoryName: "app-misc/ca-certificates",
			Arch:         "*",
			Vulnerable:   []VersionRange{{Op: "lt", Version: "20260816.3.125"}},
			Unaffected:   []VersionRange{{Op: "ge", Version: "20260816.3.125"}},
		}},
	}
	findings := Match(pkgs, []GLSA{g}, "amd64")
	if len(findings) != 1 || findings[0].Status != vuln.StatusFixed {
		t.Errorf("got %+v, want one fixed finding", findings)
	}
}
