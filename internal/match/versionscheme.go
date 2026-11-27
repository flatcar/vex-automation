package match

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/flatcar/vex-automation/internal/glsa"
	"github.com/flatcar/vex-automation/internal/portage"
)

// This file holds per-package exceptions to GLSA matching. RunGLSA calls
// evaluatePackage for every package; for most it simply calls evaluate,
// but a package listed in versionSchemes first has its versions rewritten
// so that Flatcar's and Gentoo's versions can be compared at all.

// versionTranslator rewrites an installed version and a GLSA package entry
// into versions that can be compared with each other, or explains why they
// can't be.
type versionTranslator func(installed string, affected glsa.AffectedPackage) (string, glsa.AffectedPackage, error)

// versionSchemes lists packages, by category/name, whose Flatcar versions
// follow a different scheme than the Gentoo versions in GLSAs, so comparing
// them directly gives wrong answers.
var versionSchemes = map[string]versionTranslator{
	"app-misc/ca-certificates": translateCACertificates,
}

// evaluatePackage is evaluate with the package's version scheme exception,
// if any, applied first. A range that can't be translated makes the result
// StatusUnderInvestigation, never a guessed status.
func evaluatePackage(categoryName, installedVersion string, affected glsa.AffectedPackage) (Status, string) {
	translate, ok := versionSchemes[categoryName]
	if !ok {
		return evaluate(installedVersion, affected)
	}
	translatedVersion, translatedAffected, err := translate(installedVersion, affected)
	if err != nil {
		return StatusUnderInvestigation, fmt.Sprintf("%s: %v", categoryName, err)
	}
	return evaluate(translatedVersion, translatedAffected)
}

var (
	revisionSuffix = regexp.MustCompile(`-r\d+$`)
	// gentooCACertsNSS matches Gentoo's "<bundle date>.<NSS version>"
	// ca-certificates versions, e.g. "20260816.3.125".
	gentooCACertsNSS = regexp.MustCompile(`^(\d{8})\.(\d+(?:\.\d+)*)$`)
	// gentooCACertsDate matches Gentoo's older date-only versions, e.g.
	// "20110502".
	gentooCACertsDate = regexp.MustCompile(`^\d{8}$`)
)

const (
	// Date-only Gentoo ca-certificates bundles before this date predate
	// NSS caCertsMinNSS (released August 2014), so any NSS release at or
	// above it is newer than them.
	caCertsDateOnlyCutoff = "20140101"
	caCertsMinNSS         = "3.17"
)

// translateCACertificates handles app-misc/ca-certificates, which Flatcar
// versions by the NSS release its bundle comes from (e.g. "3.125"), while
// Gentoo uses "<date>.<NSS version>" (e.g. "20260816.3.125"), or only a
// date for bundles from before 2014. Compared as-is, every Flatcar version
// sorts below every Gentoo one, so every ca-certificates GLSA would report
// it affected.
//
// Ranges are compared by their NSS version. A date-only range from before
// caCertsDateOnlyCutoff counts as older than any NSS >= caCertsMinNSS.
// Revisions are dropped on both sides, since Gentoo's and Flatcar's ebuild
// revisions are unrelated. Anything else (revision-only or glob ranges,
// newer date-only versions) is reported as untranslatable.
//
// Dropping the bundle date and revision loses information when a range
// boundary has the installed NSS version: Gentoo may have fixed a bundle by
// bumping only its date or revision, and then Flatcar's bundle could be
// either side of the fix. Revisions and any boundary other than the usual
// pair of a vulnerable "lt X" and an unaffected "ge X" (same X, no
// revision) are untranslatable. The pair itself is trusted on the
// assumption that X is Gentoo's first bundle for its NSS release, which
// holds for GLSA 202610-01 (20260816.3.125 followed 20260601.3.112.5). A
// date-only bump within one NSS release would also produce such a pair and
// can't be told apart from the GLSA alone.
func translateCACertificates(installed string, affected glsa.AffectedPackage) (string, glsa.AffectedPackage, error) {
	nss := revisionSuffix.ReplaceAllString(installed, "")
	if gentooCACertsNSS.MatchString(nss) || gentooCACertsDate.MatchString(nss) {
		return installed, affected, nil // already Gentoo's scheme
	}
	if _, err := portage.Compare(nss, caCertsMinNSS); err != nil {
		return "", affected, fmt.Errorf("installed version %q is not an NSS version: %w", installed, err)
	}

	vulnerable, err := toNSSRanges(installed, nss, affected.Vulnerable)
	if err != nil {
		return "", affected, err
	}
	unaffected, err := toNSSRanges(installed, nss, affected.Unaffected)
	if err != nil {
		return "", affected, err
	}
	if err := checkCACertsBoundary(installed, nss, affected); err != nil {
		return "", affected, err
	}
	affected.Vulnerable, affected.Unaffected = vulnerable, unaffected
	return nss, affected, nil
}

// toNSSRanges rewrites Gentoo ca-certificates ranges into NSS versions.
func toNSSRanges(installed, nss string, ranges []glsa.VersionRange) ([]glsa.VersionRange, error) {
	translated := make([]glsa.VersionRange, len(ranges))
	for i, r := range ranges {
		if !slices.Contains([]string{"lt", "le", "eq", "ge", "gt"}, r.Op) {
			return nil, fmt.Errorf("can't compare NSS version %s with GLSA range %s %s", installed, r.Op, r.Version)
		}
		version, err := toNSSVersion(installed, nss, r.Version)
		if err != nil {
			return nil, err
		}
		translated[i] = glsa.VersionRange{Op: r.Op, Version: version, Slot: r.Slot}
	}
	return translated, nil
}

// toNSSVersion turns a Gentoo version into the NSS version it bundles. An
// old date-only version becomes "0", older than any supported NSS version.
func toNSSVersion(installed, nss, gentooVersion string) (string, error) {
	if nssVersion, ok := bundledNSS(gentooVersion); ok {
		return nssVersion, nil
	}
	version := revisionSuffix.ReplaceAllString(gentooVersion, "")
	if !gentooCACertsDate.MatchString(version) || version >= caCertsDateOnlyCutoff {
		return "", fmt.Errorf("GLSA version %q has no NSS version to compare with %s", gentooVersion, installed)
	}
	if ok, err := portage.Satisfies(nss, "ge", caCertsMinNSS); err != nil || !ok {
		return "", fmt.Errorf("can't order NSS version %s against bundle date %s", installed, gentooVersion)
	}
	return "0", nil
}

// checkCACertsBoundary rejects ranges whose boundary has the installed NSS
// version, unless they are the decidable pair of a vulnerable "lt X" and
// an unaffected "ge X" with the same unrevised X (see
// translateCACertificates).
func checkCACertsBoundary(installed, nss string, affected glsa.AffectedPackage) error {
	var conditions, versions []string
	addBoundaries := func(kind string, ranges []glsa.VersionRange) {
		for _, r := range ranges {
			if hasNSSVersion(r.Version, nss) {
				conditions = append(conditions, kind+" "+r.Op)
				versions = append(versions, r.Version)
			}
		}
	}
	addBoundaries("vulnerable", affected.Vulnerable)
	addBoundaries("unaffected", affected.Unaffected)
	if len(conditions) == 0 {
		return nil
	}
	isDecidablePair := slices.Equal(conditions, []string{"vulnerable lt", "unaffected ge"}) &&
		versions[0] == versions[1] && !revisionSuffix.MatchString(versions[0])
	if !isDecidablePair {
		return fmt.Errorf("GLSA ranges %v at NSS version %s differ only in bundle date or revision, can't tell which side %s is on", versions, nss, installed)
	}
	return nil
}

// hasNSSVersion reports whether a Gentoo "<date>.<NSS version>" version
// bundles NSS version nss.
func hasNSSVersion(gentooVersion, nss string) bool {
	bundled, ok := bundledNSS(gentooVersion)
	if !ok {
		return false
	}
	order, err := portage.Compare(bundled, nss)
	return err == nil && order == 0
}

// bundledNSS returns the NSS part of a Gentoo "<date>.<NSS version>"
// version, e.g. "3.125" for "20260816.3.125-r1".
func bundledNSS(gentooVersion string) (string, bool) {
	groups := gentooCACertsNSS.FindStringSubmatch(revisionSuffix.ReplaceAllString(gentooVersion, ""))
	if groups == nil {
		return "", false
	}
	return groups[2], true
}
