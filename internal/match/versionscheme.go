package match

import (
	"fmt"
	"regexp"

	"github.com/flatcar/vex-automation/internal/glsa"
	"github.com/flatcar/vex-automation/internal/portage"
)

// versionTranslator rewrites an installed version and a GLSA package entry
// into versions that can be compared with each other, or explains why they
// can't be.
type versionTranslator func(installed string, ap glsa.AffectedPackage) (string, glsa.AffectedPackage, error)

// versionSchemes lists packages, by category/name, whose Flatcar versions
// follow a different scheme than the Gentoo versions in GLSAs, so comparing
// them directly gives wrong answers.
var versionSchemes = map[string]versionTranslator{
	"app-misc/ca-certificates": translateCACertificates,
}

// evaluatePackage is evaluate with the package's version scheme exception,
// if any, applied first. A range that can't be translated makes the result
// StatusUnderInvestigation, never a guessed status.
func evaluatePackage(categoryName, installedVersion string, ap glsa.AffectedPackage) (Status, string) {
	translate, ok := versionSchemes[categoryName]
	if !ok {
		return evaluate(installedVersion, ap)
	}
	v, tap, err := translate(installedVersion, ap)
	if err != nil {
		return StatusUnderInvestigation, fmt.Sprintf("%s: %v", categoryName, err)
	}
	return evaluate(v, tap)
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
func translateCACertificates(installed string, ap glsa.AffectedPackage) (string, glsa.AffectedPackage, error) {
	nss := revisionSuffix.ReplaceAllString(installed, "")
	if gentooCACertsNSS.MatchString(nss) || gentooCACertsDate.MatchString(nss) {
		// Already Gentoo's scheme, compare as usual.
		return installed, ap, nil
	}
	if _, err := portage.Compare(nss, caCertsMinNSS); err != nil {
		return "", ap, fmt.Errorf("installed version %q is not an NSS version: %w", installed, err)
	}

	translate := func(ranges []glsa.VersionRange) ([]glsa.VersionRange, error) {
		out := make([]glsa.VersionRange, len(ranges))
		for i, r := range ranges {
			switch r.Op {
			case "lt", "le", "eq", "ge", "gt":
			default:
				return nil, fmt.Errorf("can't compare NSS version %s with GLSA range %s %s", installed, r.Op, r.Version)
			}
			v := revisionSuffix.ReplaceAllString(r.Version, "")
			switch m := gentooCACertsNSS.FindStringSubmatch(v); {
			case m != nil:
				v = m[2]
			case gentooCACertsDate.MatchString(v) && v < caCertsDateOnlyCutoff:
				if ok, err := portage.Satisfies(nss, "ge", caCertsMinNSS); err != nil || !ok {
					return nil, fmt.Errorf("can't order NSS version %s against bundle date %s", installed, r.Version)
				}
				v = "0"
			default:
				return nil, fmt.Errorf("GLSA version %q has no NSS version to compare with %s", r.Version, installed)
			}
			out[i] = glsa.VersionRange{Op: r.Op, Version: v, Slot: r.Slot}
		}
		return out, nil
	}

	vulnerable, err := translate(ap.Vulnerable)
	if err != nil {
		return "", ap, err
	}
	unaffected, err := translate(ap.Unaffected)
	if err != nil {
		return "", ap, err
	}
	if err := checkCACertsBoundary(installed, nss, ap.Vulnerable, vulnerable, ap.Unaffected, unaffected); err != nil {
		return "", ap, err
	}
	ap.Vulnerable, ap.Unaffected = vulnerable, unaffected
	return nss, ap, nil
}

// checkCACertsBoundary rejects translations where a range boundary equals
// the installed NSS version, unless it is the decidable "lt X" / "ge X"
// pair with the same unrevised X (see translateCACertificates).
func checkCACertsBoundary(installed, nss string, origVuln, vuln, origUnaff, unaff []glsa.VersionRange) error {
	var ops []string
	var origs []string
	collect := func(orig, tr []glsa.VersionRange, kind string) {
		for i, r := range tr {
			if c, err := portage.Compare(r.Version, nss); err == nil && c == 0 {
				ops = append(ops, kind+" "+r.Op)
				origs = append(origs, orig[i].Version)
			}
		}
	}
	collect(origVuln, vuln, "vulnerable")
	collect(origUnaff, unaff, "unaffected")
	if len(ops) == 0 {
		return nil
	}
	pair := len(ops) == 2 && ops[0] == "vulnerable lt" && ops[1] == "unaffected ge" &&
		origs[0] == origs[1] && !revisionSuffix.MatchString(origs[0])
	if !pair {
		return fmt.Errorf("GLSA ranges %v at NSS version %s differ only in bundle date or revision, can't tell which side %s is on", origs, nss, installed)
	}
	return nil
}
