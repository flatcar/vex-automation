package match

import (
	"github.com/flatcar/vex-automation/internal/vuln"

	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/flatcar/vex-automation/internal/osv"
)

// This file corrects curl's GLSA findings using curl's own advisories. Only
// the diff command uses it (see cli.addOSVFindings for why): RunGLSA makes
// the findings, CurlAdvisoryIDs says which advisories to fetch from
// OSV.dev, and ApplyCurlAdvisories rewrites the findings they disprove.

// curlPackage is the ebuild whose GLSA findings ApplyCurlAdvisories
// rechecks.
const curlPackage = "net-misc/curl"

// curlAdvisoryPrefix prefixes curl's own advisories on OSV.dev, which curl
// publishes per CVE (e.g. "CURL-CVE-2024-11053") with every affected
// release listed.
const curlAdvisoryPrefix = "CURL-"

// plainCurlVersion matches Gentoo curl versions that map one-to-one to an
// upstream release once any "-rN" revision is stripped. Patchset,
// prerelease and live versions (e.g. "_p1", "_rc1", "9999") do not.
var plainCurlVersion = regexp.MustCompile(`^\d+\.\d+(\.\d+)*(-r\d+)?$`)

// CurlAdvisoryIDs returns the OSV.dev IDs of curl's own advisories for
// every CVE that a GLSA reports curl as affected by, sorted and
// deduplicated.
func CurlAdvisoryIDs(findings []vuln.Finding) []string {
	var ids []string
	for _, finding := range findings {
		if isCurlGLSAAffected(finding) {
			ids = append(ids, curlAdvisoryPrefix+finding.CVE)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// ApplyCurlAdvisories rechecks GLSA "affected" findings for curl against
// curl's own advisories (keyed by OSV.dev ID, see CurlAdvisoryIDs). Gentoo
// GLSAs for curl bundle years of CVEs under one "lt <latest>" range, so a
// release whose curl already contained a fix still matches. When curl's
// advisory exists and does not list the installed upstream version, the
// finding becomes not_affected. Findings without an advisory, or whose
// version does not map to an upstream release (see plainCurlVersion), are
// kept. The input is not modified.
func ApplyCurlAdvisories(findings []vuln.Finding, advisories map[string]osv.Vulnerability) []vuln.Finding {
	rechecked := slices.Clone(findings)
	for i, finding := range rechecked {
		if !isCurlGLSAAffected(finding) {
			continue
		}
		advisory, ok := advisories[curlAdvisoryPrefix+finding.CVE]
		if !ok || len(advisory.AffectedVersions) == 0 || !plainCurlVersion.MatchString(finding.Package.Version) {
			continue
		}
		upstreamVersion, _, _ := strings.Cut(finding.Package.Version, "-r")
		if slices.Contains(advisory.AffectedVersions, upstreamVersion) {
			continue
		}
		rechecked[i].Status = vuln.StatusNotAffected
		rechecked[i].Note = fmt.Sprintf("curl's own advisory %s does not list version %s as affected", advisory.ID, upstreamVersion)
	}
	return rechecked
}

func isCurlGLSAAffected(finding vuln.Finding) bool {
	return finding.Source == vuln.SourceGLSA && finding.Status == vuln.StatusAffected && finding.Package.FullName() == curlPackage
}
