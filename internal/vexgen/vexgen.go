// Package vexgen turns vulnerability findings into an OpenVEX document,
// using the official github.com/openvex/go-vex library. See README.md.
package vexgen

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/flatcar/vex-automation/internal/vuln"
	"github.com/openvex/go-vex/pkg/vex"
)

// Metadata holds the document-level fields.
type Metadata struct {
	Author string
	// ProductID identifies the release, e.g.
	// "pkg:generic/flatcar-container-linux@4593.2.4?channel=stable".
	ProductID string
	// Timestamp defaults to the current time.
	Timestamp time.Time
	// Tooling describes how the document was made, e.g. which sources were used.
	Tooling string
}

// sourceLabels names each finding source in remediation text, in the
// order they are listed. A new source must be added here to be cited.
var sourceLabels = []struct{ source, label string }{
	{vuln.SourceGLSA, "Gentoo GLSA"},
	{vuln.SourceOSV, "OSV.dev advisory"},
}

// Build makes a document with one statement per vulnerability. A release
// can't be both fixed and affected, so when the findings of a
// vulnerability disagree, the statement takes the most severe status (see
// vuln.StatusPrecedence) and lists the packages with that status.
func Build(findings []vuln.Finding, meta Metadata) (*vex.VEX, error) {
	if meta.ProductID == "" {
		return nil, errors.New("vexgen: Metadata.ProductID must not be empty")
	}
	timestamp := meta.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	doc := vex.New() // Author defaults to vex.DefaultAuthor, "Unknown Author".
	if meta.Author != "" {
		doc.Author = meta.Author
	}
	doc.Tooling = meta.Tooling
	doc.Timestamp = &timestamp

	findingsByID := map[string][]vuln.Finding{}
	for _, finding := range findings {
		findingsByID[finding.CVE] = append(findingsByID[finding.CVE], finding)
	}
	for _, id := range slices.Sorted(maps.Keys(findingsByID)) {
		worst := mostSevere(findingsByID[id])
		if worst == nil {
			return nil, fmt.Errorf("vexgen: %s has findings with unknown status", id)
		}
		statement := newStatement(id, worst, meta.ProductID)
		statement.Timestamp = &timestamp
		doc.Statements = append(doc.Statements, statement)
	}

	if _, err := doc.GenerateCanonicalID(); err != nil {
		return nil, fmt.Errorf("vexgen: generating document ID: %w", err)
	}
	return &doc, nil
}

// mostSevere returns the findings that have the most severe status, or
// nil if no finding has a known status.
func mostSevere(findings []vuln.Finding) []vuln.Finding {
	for _, status := range vuln.StatusPrecedence {
		var withStatus []vuln.Finding
		for _, finding := range findings {
			if finding.Status == status {
				withStatus = append(withStatus, finding)
			}
		}
		if len(withStatus) > 0 {
			return withStatus
		}
	}
	return nil
}

// newStatement describes one vulnerability; all findings share its status.
func newStatement(id string, findings []vuln.Finding, productID string) vex.Statement {
	status := findings[0].Status
	statement := vex.Statement{
		Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(id)},
		Status:        vex.Status(status),
		StatusNotes:   statusNotes(findings),
		Products: []vex.Product{{
			Component:     vex.Component{ID: productID},
			Subcomponents: subcomponents(findings),
		}},
	}
	switch status {
	case vuln.StatusAffected:
		statement.ActionStatement = actionStatement(id, findings)
	case vuln.StatusNotAffected:
		statement.Justification = vex.VulnerableCodeNotPresent
		statement.ImpactStatement = "The installed version is outside every vulnerable version range listed by the advisory."
	}
	return statement
}

// statusNotes joins the distinct notes of findings, e.g. why a
// vulnerability is under investigation.
func statusNotes(findings []vuln.Finding) string {
	var notes []string
	for _, finding := range findings {
		if finding.Note != "" {
			notes = append(notes, finding.Note)
		}
	}
	return strings.Join(sortedUnique(notes), "; ")
}

// subcomponents lists the affected packages by purl.
func subcomponents(findings []vuln.Finding) []vex.Subcomponent {
	var purls []string
	for _, finding := range findings {
		purls = append(purls, finding.Package.PURL)
	}
	var subs []vex.Subcomponent
	for _, purl := range sortedUnique(purls) {
		subs = append(subs, vex.Subcomponent{
			Component: vex.Component{Identifiers: map[vex.IdentifierType]string{vex.PURL: purl}},
		})
	}
	return subs
}

// actionStatement tells the reader to update, citing the advisories per
// source, e.g. "... (see Gentoo GLSA 202604-03; OSV.dev advisory GO-2026-1)."
func actionStatement(id string, findings []vuln.Finding) string {
	var citations []string
	for _, source := range sourceLabels {
		var refIDs []string
		for _, finding := range findings {
			if finding.Source == source.source && finding.RefID != "" {
				refIDs = append(refIDs, finding.RefID)
			}
		}
		if len(refIDs) > 0 {
			citations = append(citations, source.label+" "+strings.Join(sortedUnique(refIDs), ", "))
		}
	}

	// OSV.dev vulnerabilities without a CVE have IDs like "GHSA-...".
	kind := "vulnerability"
	if strings.HasPrefix(id, "CVE-") {
		kind = "CVE"
	}
	message := "Update the affected package(s) to a version that resolves this " + kind
	if len(citations) > 0 {
		message += " (see " + strings.Join(citations, "; ") + ")"
	}
	return message + "."
}

func sortedUnique(values []string) []string {
	values = slices.Clone(values)
	slices.Sort(values)
	return slices.Compact(values)
}
