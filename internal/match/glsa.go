// Package match matches SBOM packages against the vulnerability sources:
// ebuilds against Gentoo's GLSAs (RunGLSA), golang/cargo modules against
// OSV.dev (RunOSV). Both produce vuln.Findings.
package match

import (
	"log/slog"
	"regexp"
	"strings"
	"unicode"

	"github.com/flatcar/vex-automation/internal/glsa"
	"github.com/flatcar/vex-automation/internal/portage"
	"github.com/flatcar/vex-automation/internal/sbom"
	"github.com/flatcar/vex-automation/internal/vuln"
)

const slotNote = "GLSA range is restricted to a slot that can't be determined from the SBOM"

// RunGLSA matches every ebuild package against every GLSA for arch, giving
// one vuln.Finding per CVE and package the GLSA names. A GLSA without CVEs is
// reported as "GLSA-<id>". A version that can't be evaluated is reported
// as under investigation rather than dropped.
//
// This mirrors what Flatcar's build already does with Gentoo's glsa-check,
// so the VEX document agrees with the check that gates releases.
func RunGLSA(pkgs []sbom.Package, glsas []glsa.GLSA, arch string) []vuln.Finding {
	// GLSAs name packages as "category/name"; an image may ship several
	// versions (slots) of one package.
	installed := map[string][]sbom.Package{}
	for _, pkg := range pkgs {
		installed[pkg.FullName()] = append(installed[pkg.FullName()], pkg)
	}

	var findings []vuln.Finding
	for _, advisory := range glsas {
		ids := advisory.CVEs
		if len(ids) == 0 {
			ids = []string{"GLSA-" + advisory.ID}
		}
		for _, affected := range advisory.Packages {
			if !affected.MatchesArch(arch) {
				continue
			}
			for _, pkg := range installed[affected.CategoryName] {
				status, note := evaluatePackage(affected.CategoryName, pkg.Version, affected)
				if status == vuln.StatusUnderInvestigation {
					slog.Info("cannot evaluate GLSA ranges, reporting as under investigation",
						"package", pkg.FullName(), "version", pkg.Version, "glsa", advisory.ID, "reason", note)
				}
				for _, id := range ids {
					findings = append(findings, vuln.Finding{
						CVE: id, Source: vuln.SourceGLSA, RefID: advisory.ID, Package: pkg, Status: status, Note: note,
					})
				}
			}
		}
	}
	vuln.Sort(findings)
	return findings
}

// evaluate classifies an installed version against a GLSA package entry
// the way glsa-check does:
//
//  1. in an <unaffected> range: fixed
//  2. otherwise in a <vulnerable> range: affected
//  3. otherwise newer than some fix: fixed (glsa-check only says "not
//     vulnerable", e.g. samba 4.22 against "rge 4.11.6")
//  4. otherwise: not affected
//
// A range limited to a slot we can't resolve only "possibly" matches. If
// that could change the answer, the result is under investigation.
func evaluate(version string, affected glsa.AffectedPackage) (vuln.Status, string) {
	matcher := newVersionMatcher(version, affected)

	fixed, err := matcher.match(affected.Unaffected)
	if err != nil {
		return vuln.StatusUnderInvestigation, err.Error()
	}
	if fixed.certain {
		return vuln.StatusFixed, ""
	}

	vulnerable, err := matcher.match(affected.Vulnerable)
	if err != nil {
		return vuln.StatusUnderInvestigation, err.Error()
	}
	if vulnerable.certain && !fixed.possible {
		return vuln.StatusAffected, ""
	}
	if vulnerable.certain || vulnerable.possible {
		return vuln.StatusUnderInvestigation, slotNote
	}

	newerThanFix, err := matcher.match(lowerBounds(affected.Unaffected))
	if err != nil {
		return vuln.StatusUnderInvestigation, err.Error()
	}
	switch {
	case newerThanFix.certain:
		return vuln.StatusFixed, ""
	case fixed.possible || newerThanFix.possible:
		return vuln.StatusUnderInvestigation, slotNote
	default:
		return vuln.StatusNotAffected, ""
	}
}

// lowerBounds turns the ranges that start at a fix ("ge", "gt" and their
// revision-only forms) into plain "ge"/"gt" ranges, and drops the others.
func lowerBounds(ranges []glsa.VersionRange) []glsa.VersionRange {
	var bounds []glsa.VersionRange
	for _, r := range ranges {
		switch r.Op {
		case "ge", "rge":
			r.Op = "ge"
		case "gt", "rgt":
			r.Op = "gt"
		default:
			continue
		}
		bounds = append(bounds, r)
	}
	return bounds
}

// rangeMatch is the result of checking a version against some ranges.
type rangeMatch struct {
	certain  bool // a range matches and its slot applies
	possible bool // a range matches, but we can't tell if its slot applies
}

type slotApplies int

const (
	slotYes slotApplies = iota
	slotNo
	slotUnknown
)

// numericSlot matches slots named after a version branch, e.g. "3.11" or "17".
var numericSlot = regexp.MustCompile(`^\d+(?:\.\d+)*$`)

// versionMatcher checks one installed version against GLSA ranges.
//
// The SBOM doesn't record SLOTs, so a slot is only resolved when that is
// safe: Gentoo often names slots after version branches (python "3.11",
// llvm "17"). If some range of the entry names the installed version's
// branch, numeric slots are read as branches. Every other slot ("0",
// "esr", or webkit-gtk's "4" for version 2.44) is unknown.
type versionMatcher struct {
	version     string
	branchSlots bool
}

func newVersionMatcher(version string, affected glsa.AffectedPackage) versionMatcher {
	matcher := versionMatcher{version: version}
	for _, ranges := range [][]glsa.VersionRange{affected.Vulnerable, affected.Unaffected} {
		for _, r := range ranges {
			if isBranchOf(r.Slot, version) {
				matcher.branchSlots = true
			}
		}
	}
	return matcher
}

func (m versionMatcher) match(ranges []glsa.VersionRange) (rangeMatch, error) {
	var result rangeMatch
	for _, r := range ranges {
		applies := m.slotApplies(r.Slot)
		if applies == slotNo {
			continue
		}
		matches, err := portage.Satisfies(m.version, r.Op, r.Version)
		if err != nil {
			return rangeMatch{}, err
		}
		if matches && applies == slotYes {
			result.certain = true
		}
		if matches && applies == slotUnknown {
			result.possible = true
		}
	}
	return result, nil
}

func (m versionMatcher) slotApplies(slot string) slotApplies {
	switch {
	case slot == "" || slot == "*":
		return slotYes
	case !m.branchSlots || slot == "0" || !numericSlot.MatchString(slot):
		return slotUnknown
	case isBranchOf(slot, m.version):
		return slotYes
	default:
		return slotNo
	}
}

// isBranchOf reports whether a numeric slot is a version branch of
// version: "3.12" is one of "3.12.1", but not of "3.121".
func isBranchOf(slot, version string) bool {
	if slot == "0" || !numericSlot.MatchString(slot) || !strings.HasPrefix(version, slot) {
		return false
	}
	rest := version[len(slot):]
	return rest == "" || !unicode.IsDigit(rune(rest[0]))
}
