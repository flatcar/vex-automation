// Package match determines, for each installed ebuild package, whether it is
// affected by or already fixed against the CVEs described in a GLSA corpus.
package match

import (
	"log/slog"
	"sort"

	"github.com/flatcar/vex-automation/internal/glsa"
	"github.com/flatcar/vex-automation/internal/portage"
	"github.com/flatcar/vex-automation/internal/sbom"
)

// Finding is the result of matching a single installed package against a
// single CVE referenced by a GLSA.
type Finding struct {
	// CVE is the vulnerability identifier, e.g. "CVE-2026-33150".
	CVE string
	// GLSAID is the advisory that referenced this CVE, e.g. "202604-03".
	GLSAID string
	// Package is the installed package this finding is about.
	Package sbom.Package
	// Affected is true if the installed version matches the GLSA's
	// vulnerable range (and not its unaffected range); false means the
	// package is present but already at/past a fixed version.
	Affected bool
}

// Run matches every ebuild package in pkgs against every GLSA in glsas,
// restricted to entries applicable to arch (e.g. "amd64"). It returns one
// Finding per (CVE, package) pair where the GLSA's affected-package name
// matches an installed package's category/name.
//
// Version strings that fail to parse are skipped with a warning logged
// rather than aborting the whole run — a single malformed or highly unusual
// version should not prevent every other package from being checked.
func Run(pkgs []sbom.Package, glsas []glsa.GLSA, arch string) []Finding {
	byCategoryName := make(map[string][]sbom.Package, len(pkgs))
	for _, p := range pkgs {
		byCategoryName[p.CategoryName()] = append(byCategoryName[p.CategoryName()], p)
	}

	var findings []Finding
	for _, g := range glsas {
		if len(g.CVEs) == 0 {
			continue // nothing to report without a CVE identifier
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
				affected, ok := isAffected(pkg.Version, ap)
				if !ok {
					slog.Warn("skipping version comparison",
						"package", pkg.CategoryName(), "version", pkg.Version, "glsa", g.ID)
					continue
				}

				for _, cve := range g.CVEs {
					findings = append(findings, Finding{
						CVE:      cve,
						GLSAID:   g.ID,
						Package:  pkg,
						Affected: affected,
					})
				}
			}
		}
	}

	sortFindings(findings)
	return findings
}

// isAffected reports whether installedVersion is vulnerable per ap: it must
// satisfy at least one <vulnerable> range and must not satisfy any
// <unaffected> range. The second return value is false if any range's
// version string could not be parsed, in which case the caller should treat
// the result as unknown rather than acting on it.
func isAffected(installedVersion string, ap glsa.AffectedPackage) (affected bool, ok bool) {
	vulnerable := false
	for _, r := range ap.Vulnerable {
		match, err := portage.Satisfies(installedVersion, r.Op, r.Version)
		if err != nil {
			return false, false
		}
		if match {
			vulnerable = true
			break
		}
	}
	if !vulnerable {
		return false, true
	}

	for _, r := range ap.Unaffected {
		match, err := portage.Satisfies(installedVersion, r.Op, r.Version)
		if err != nil {
			return false, false
		}
		if match {
			return false, true // an unaffected range takes precedence
		}
	}

	return true, true
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
		return a.Package.Version < b.Package.Version
	})
}
