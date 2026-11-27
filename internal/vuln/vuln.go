// Package vuln is the vocabulary shared by vulnerability sources and
// outputs: a Finding says how one vulnerability affects one installed
// package, with a VEX Status. See README.md.
package vuln

import (
	"cmp"
	"slices"

	"github.com/flatcar/vex-automation/internal/sbom"
)

// Sources a Finding can come from.
const (
	SourceGLSA = "glsa"
	SourceOSV  = "osv"
)

// Status is a VEX status, named as in OpenVEX.
type Status string

const (
	// StatusAffected means the installed version is in a vulnerable range.
	StatusAffected Status = "affected"
	// StatusFixed means the installed version contains the fix.
	StatusFixed Status = "fixed"
	// StatusNotAffected means the installed version is in no vulnerable range,
	// e.g. it predates the vulnerable code.
	StatusNotAffected Status = "not_affected"
	// StatusUnderInvestigation means the version could not be evaluated;
	// Finding.Note says why.
	StatusUnderInvestigation Status = "under_investigation"
)

// StatusPrecedence lists the statuses from most to least severe. When
// findings disagree about one vulnerability, the most severe one wins.
var StatusPrecedence = []Status{StatusAffected, StatusUnderInvestigation, StatusFixed, StatusNotAffected}

// Severity is s's position in StatusPrecedence (0 is the most severe).
func Severity(s Status) int {
	if i := slices.Index(StatusPrecedence, s); i >= 0 {
		return i
	}
	return len(StatusPrecedence)
}

// Finding says how one vulnerability affects one installed package,
// according to one advisory.
//
// One vulnerability often gets several findings: several advisories name
// it, or several packages (or versions of one package) ship it. Each
// finding is kept separate here; vexgen and diff group them by CVE and
// let the most severe status win (see StatusPrecedence).
type Finding struct {
	// CVE is the vulnerability ID, and the key findings are grouped by
	// later. Without a CVE it is the source's own ID: an OSV.dev ID, or
	// "GLSA-<id>".
	CVE string
	// Source is SourceGLSA or SourceOSV.
	Source string
	// RefID is the advisory that produced the finding: a GLSA ID such as
	// "202604-03", or an OSV.dev ID.
	RefID   string
	Package sbom.Package
	Status  Status
	// Note explains the status, e.g. why it is under investigation.
	Note string
}

// Sort orders findings so that the same input always gives the same
// output.
func Sort(findings []Finding) {
	slices.SortStableFunc(findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(a.CVE, b.CVE),
			cmp.Compare(a.Package.FullName(), b.Package.FullName()),
			cmp.Compare(a.Package.Ecosystem, b.Package.Ecosystem),
			cmp.Compare(a.Package.Version, b.Package.Version),
			cmp.Compare(a.Source, b.Source),
			cmp.Compare(a.RefID, b.RefID),
		)
	})
}
