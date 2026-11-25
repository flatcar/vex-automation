package match

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/flatcar/vex-automation/internal/osv"
)

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
func CurlAdvisoryIDs(findings []Finding) []string {
	seen := map[string]bool{}
	var ids []string
	for _, f := range findings {
		if isCurlGLSAAffected(f) && !seen[f.CVE] {
			seen[f.CVE] = true
			ids = append(ids, curlAdvisoryPrefix+f.CVE)
		}
	}
	sort.Strings(ids)
	return ids
}

// ApplyCurlAdvisories rechecks GLSA "affected" findings for curl against
// curl's own advisories (keyed by OSV.dev ID, see CurlAdvisoryIDs). Gentoo
// GLSAs for curl bundle years of CVEs under one "lt <latest>" range, so a
// release whose curl already contained a fix still matches. When curl's
// advisory exists and does not list the installed upstream version, the
// finding becomes not_affected. Findings without an advisory, or whose
// version does not map to an upstream release (see plainCurlVersion), are
// kept. The input is not modified.
func ApplyCurlAdvisories(findings []Finding, advisories map[string]osv.Vulnerability) []Finding {
	out := slices.Clone(findings)
	for i, f := range out {
		if !isCurlGLSAAffected(f) {
			continue
		}
		adv, ok := advisories[curlAdvisoryPrefix+f.CVE]
		if !ok || len(adv.AffectedVersions) == 0 || !plainCurlVersion.MatchString(f.Package.Version) {
			continue
		}
		upstream, _, _ := strings.Cut(f.Package.Version, "-r")
		if slices.Contains(adv.AffectedVersions, upstream) {
			continue
		}
		out[i].Status = StatusNotAffected
		out[i].Note = fmt.Sprintf("curl's own advisory %s does not list version %s as affected", adv.ID, upstream)
	}
	return out
}

func isCurlGLSAAffected(f Finding) bool {
	return f.Source == SourceGLSA && f.Status == StatusAffected && f.Package.CategoryName() == curlPackage
}
