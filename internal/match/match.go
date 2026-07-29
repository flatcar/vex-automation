// Package match determines, for each installed package, whether it is
// affected by or already fixed against known vulnerabilities: ebuild
// packages against the GLSA corpus (Run), and golang/cargo packages against
// OSV.dev (RunOSV).
package match

import (
	"context"
	"log/slog"
	"sort"

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

// Finding is the result of matching a single installed package against a
// single vulnerability referenced by one of the supported sources.
type Finding struct {
	// CVE is the vulnerability identifier, e.g. "CVE-2026-33150". For
	// sources where a CVE alias isn't available (some OSV.dev records have
	// none), this falls back to that source's own identifier, e.g. a GHSA
	// ID.
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
	// Affected is true if the installed version matches the source's
	// vulnerable range (and not its unaffected range); false means the
	// package is present but already at/past a fixed version. OSV.dev
	// findings are always Affected=true (see RunOSV).
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
						Source:   SourceGLSA,
						RefID:    g.ID,
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
// returned here has Affected=true. OSV.dev has no equivalent of GLSA's
// <unaffected> ranges to prove a specific version is fixed — it simply
// doesn't return a vulnerability ID that doesn't apply to the version
// queried, so there is no "fixed" case to represent for this source.
func RunOSV(ctx context.Context, pkgs []sbom.Package, client *osv.Client) ([]Finding, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}

	// Build the exact purl to query for each package: type/name@version
	// only, with any subpath or qualifiers from the original SBOM purl
	// stripped, since those aren't part of package identity for
	// vulnerability matching (see sbom.Package.PURL's doc comment on why
	// the original purl is still preserved for VEX output).
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
			findings = append(findings, Finding{
				CVE:      v.CVE(),
				Source:   SourceOSV,
				RefID:    v.ID,
				Package:  pkg,
				Affected: true,
			})
		}
	}

	sortFindings(findings)
	return findings, nil
}
