// Package match determines, for each installed package, whether it is
// affected by or already fixed against known vulnerabilities: ebuild
// packages against the GLSA corpus (Run), and golang/cargo packages against
// OSV.dev (RunOSV).
package match

import (
	"context"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/flatcar/vex-automation/internal/glsa"
	"github.com/flatcar/vex-automation/internal/osv"
	"github.com/flatcar/vex-automation/internal/portage"
	"github.com/flatcar/vex-automation/internal/sbom"
)

// Source identifies which vulnerability source a Finding came from, so
// multiple sources can share the same Finding/vexgen pipeline without their
// results being confused for one another.
const (
	SourceGLSA = "glsa"
	SourceOSV  = "osv"
)

// Status is the VEX status of a single Finding. The values match the
// OpenVEX status names.
type Status string

const (
	// StatusAffected means the installed version is in a vulnerable range.
	StatusAffected Status = "affected"
	// StatusFixed means the installed version is in a range the source
	// lists as unaffected, i.e. it already contains the fix.
	StatusFixed Status = "fixed"
	// StatusNotAffected means the source lists the package, but the
	// installed version is in none of its vulnerable or unaffected ranges,
	// e.g. it predates the vulnerable code.
	StatusNotAffected Status = "not_affected"
	// StatusUnderInvestigation means the installed version could not be
	// evaluated against the source's ranges (unparseable version, unknown
	// range operator, or a slot-restricted range whose applicability can't
	// be determined from the SBOM).
	StatusUnderInvestigation Status = "under_investigation"
)

// Finding is the result of matching a single installed package against a
// single vulnerability referenced by one of the supported sources.
type Finding struct {
	// CVE is the vulnerability identifier, e.g. "CVE-2026-33150". For
	// sources where a CVE alias isn't available, this falls back to that
	// source's own identifier: the OSV.dev ID (e.g. a GHSA ID), or
	// "GLSA-<id>" for a GLSA that references no CVE.
	CVE string
	// Source is which vulnerability source produced this Finding: one of
	// SourceGLSA or SourceOSV.
	Source string
	// RefID is the source-specific advisory identifier: a GLSA ID (e.g.
	// "202604-03") for SourceGLSA, or an OSV.dev vulnerability ID (e.g.
	// "GHSA-xxxx-xxxx-xxxx") for SourceOSV.
	RefID string
	// Package is the installed package this finding is about.
	Package sbom.Package
	// Status is the VEX status of Package with respect to CVE. OSV.dev
	// findings are always StatusAffected (see RunOSV).
	Status Status
	// Note optionally explains Status, e.g. why a finding is under
	// investigation. Empty for ordinary affected/fixed results.
	Note string
}

// Run matches every ebuild package in pkgs against every GLSA in glsas,
// restricted to entries applicable to arch (e.g. "amd64"). It returns one
// Finding per (CVE, package) pair where the GLSA's affected-package name
// matches an installed package's category/name. A GLSA that references no
// CVE is reported under the identifier "GLSA-<id>" instead of being dropped.
//
// A version comparison that can't be evaluated (e.g. an unparseable version
// string) doesn't abort the run: it's logged and reported as
// StatusUnderInvestigation, so the vulnerability stays visible in the VEX
// document instead of silently disappearing.
func Run(pkgs []sbom.Package, glsas []glsa.GLSA, arch string) []Finding {
	byCategoryName := make(map[string][]sbom.Package, len(pkgs))
	for _, p := range pkgs {
		byCategoryName[p.CategoryName()] = append(byCategoryName[p.CategoryName()], p)
	}

	var findings []Finding
	for _, g := range glsas {
		ids := g.CVEs
		if len(ids) == 0 {
			ids = []string{"GLSA-" + g.ID}
		}

		for _, ap := range g.Packages {
			if !ap.MatchesArch(arch) {
				continue
			}

			installed, ok := byCategoryName[ap.CategoryName]
			if !ok {
				continue // package not present in this SBOM at all
			}

			for _, pkg := range installed {
				status, note := evaluatePackage(ap.CategoryName, pkg.Version, ap)
				if status == StatusUnderInvestigation {
					slog.Warn("cannot evaluate GLSA ranges, reporting as under investigation",
						"package", pkg.CategoryName(), "version", pkg.Version, "glsa", g.ID, "reason", note)
				}

				for _, id := range ids {
					findings = append(findings, Finding{
						CVE:     id,
						Source:  SourceGLSA,
						RefID:   g.ID,
						Package: pkg,
						Status:  status,
						Note:    note,
					})
				}
			}
		}
	}

	sortFindings(findings)
	return findings
}

// slotApplicability describes whether a slot-restricted GLSA range applies
// to an installed version whose SLOT isn't known (Flatcar's SBOM doesn't
// record it).
type slotApplicability int

const (
	slotApplies slotApplicability = iota
	slotDoesNotApply
	slotUnknown
)

// numericSlot matches slots that name a version branch, e.g. "3.11" or "17".
var numericSlot = regexp.MustCompile(`^\d+(?:\.\d+)*$`)

// rangeApplies decides whether a range with the given slot applies to
// installedVersion. Unslotted ("" or "*") ranges always apply. Gentoo
// commonly names multi-version slots after their version branch (python
// "3.11", llvm "17", postgresql "16"), so when branchSlots is true (some
// numeric slot of the same GLSA package entry is a component prefix of
// installedVersion) a numeric slot applies exactly when it is such a
// prefix. Otherwise the slot naming doesn't follow the version (e.g.
// webkit-gtk slot "4" for version 2.44), and like slot "0", subslots and
// named slots such as "esr", it can't be resolved without the real SLOT.
func rangeApplies(slot, installedVersion string, branchSlots bool) slotApplicability {
	if slot == "" || slot == "*" {
		return slotApplies
	}
	if !branchSlots || slot == "0" || !numericSlot.MatchString(slot) {
		return slotUnknown
	}
	if isBranchOf(slot, installedVersion) {
		return slotApplies
	}
	return slotDoesNotApply
}

// isBranchOf reports whether the numeric slot is a component prefix of
// version, e.g. "3.12" of "3.12.1" but not of "3.121".
func isBranchOf(slot, version string) bool {
	if slot == "0" || !numericSlot.MatchString(slot) || !strings.HasPrefix(version, slot) {
		return false
	}
	rest := version[len(slot):]
	return rest == "" || !unicode.IsDigit(rune(rest[0]))
}

// evaluate classifies installedVersion against ap's ranges, mirroring
// glsa-check: a version in any <unaffected> range is fixed; otherwise a
// version in any <vulnerable> range is affected; otherwise it is fixed if
// it is newer than some fix (see newerThanAFix) and not affected if not. Ranges are first filtered by slot (see rangeApplies). A
// matching range whose slot can't be resolved makes the answer uncertain
// only when it could change it, in which case the result is
// StatusUnderInvestigation. The returned note explains that status.
func evaluate(installedVersion string, ap glsa.AffectedPackage) (Status, string) {
	branchSlots := false
	for _, r := range append(append([]glsa.VersionRange{}, ap.Vulnerable...), ap.Unaffected...) {
		if isBranchOf(r.Slot, installedVersion) {
			branchSlots = true
			break
		}
	}

	// matches reports whether some applicable range matches (sure), and
	// whether some range with an unresolvable slot matches (maybe).
	matches := func(ranges []glsa.VersionRange) (sure, maybe bool, err error) {
		for _, r := range ranges {
			applies := rangeApplies(r.Slot, installedVersion, branchSlots)
			if applies == slotDoesNotApply {
				continue
			}
			ok, err := portage.Satisfies(installedVersion, r.Op, r.Version)
			if err != nil {
				return false, false, err
			}
			if ok && applies == slotApplies {
				sure = true
			} else if ok {
				maybe = true
			}
		}
		return sure, maybe, nil
	}

	fixed, maybeFixed, err := matches(ap.Unaffected)
	if err != nil {
		return StatusUnderInvestigation, err.Error()
	}
	if fixed {
		return StatusFixed, ""
	}
	vulnerable, maybeVulnerable, err := matches(ap.Vulnerable)
	if err != nil {
		return StatusUnderInvestigation, err.Error()
	}

	const slotNote = "GLSA range is restricted to a slot that can't be determined from the SBOM"
	switch {
	case vulnerable && !maybeFixed:
		return StatusAffected, ""
	case vulnerable || maybeVulnerable:
		return StatusUnderInvestigation, slotNote
	case maybeFixed || newerThanAFix(installedVersion, ap.Unaffected, branchSlots):
		return StatusFixed, ""
	default:
		return StatusNotAffected, ""
	}
}

// newerThanAFix reports whether installedVersion is at or above the lower
// bound of some applicable ge/gt/rge/rgt <unaffected> range. glsa-check
// calls such a version not vulnerable even when no range matches it
// exactly (e.g. samba 4.22.5 against "rge 4.11.6", which only covers
// 4.11.6-rN), but it is a release that carries the fix, so VEX should say
// fixed, not that the vulnerable code was never present.
func newerThanAFix(installedVersion string, unaffected []glsa.VersionRange, branchSlots bool) bool {
	for _, r := range unaffected {
		if rangeApplies(r.Slot, installedVersion, branchSlots) == slotDoesNotApply {
			continue
		}
		var op string
		switch r.Op {
		case "ge", "rge":
			op = "ge"
		case "gt", "rgt":
			op = "gt"
		default:
			continue
		}
		if ok, err := portage.Satisfies(installedVersion, op, r.Version); err == nil && ok {
			return true
		}
	}
	return false
}

// sortFindings orders findings deterministically so that repeated runs over
// the same inputs produce byte-identical output.
func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.CVE != b.CVE {
			return a.CVE < b.CVE
		}
		if a.Package.CategoryName() != b.Package.CategoryName() {
			return a.Package.CategoryName() < b.Package.CategoryName()
		}
		if a.Package.Version != b.Package.Version {
			return a.Package.Version < b.Package.Version
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.RefID < b.RefID
	})
}

// RunOSV matches every OSV-queryable package in pkgs (golang/cargo purls
// extracted by sbom.Load into Document.OSVPackages) against OSV.dev via
// client, returning one Finding per (package, vulnerability) pair OSV.dev
// reports as affecting that package's exact installed version.
//
// Unlike Run's GLSA matching, there is no local version-range comparison
// here: since each query already targets pkgs' exact installed version,
// every result OSV.dev returns already applies to it, so every Finding
// returned here has Status=StatusAffected. OSV.dev has no equivalent of GLSA's
// <unaffected> ranges to prove a specific version is fixed — it simply
// doesn't return a vulnerability ID that doesn't apply to the version
// queried, so there is no "fixed" case to represent for this source.
func RunOSV(ctx context.Context, pkgs []sbom.Package, client *osv.Client) ([]Finding, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}

	// Build the purl to query for each package as type/name@version, where
	// sbom.Load has already folded any golang subpath into Name (the
	// subpath is part of the Go module path, e.g. ".../jwt@v4.5.1#v4" is
	// module ".../jwt/v4") and normalized Version. Qualifiers are dropped.
	// The original SBOM purl is still kept in Package.PURL for VEX output.
	queryPURLs := make([]string, len(pkgs))
	for i, pkg := range pkgs {
		queryPURLs[i] = "pkg:" + pkg.Category + "/" + pkg.Name + "@" + pkg.Version
	}

	results, err := client.Query(ctx, queryPURLs)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for i, pkg := range pkgs {
		for _, v := range results[queryPURLs[i]] {
			for _, id := range v.CVEs() {
				findings = append(findings, Finding{
					CVE:     id,
					Source:  SourceOSV,
					RefID:   v.ID,
					Package: pkg,
					Status:  StatusAffected,
				})
			}
		}
	}

	sortFindings(findings)
	return findings, nil
}
