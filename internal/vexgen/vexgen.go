// Package vexgen builds an OpenVEX document from match.Finding results,
// using the official github.com/openvex/go-vex library.
package vexgen

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/flatcar/vex-automation/internal/match"
)

// Metadata configures the VEX document's top-level fields.
type Metadata struct {
	// Author identifies who/what generated this document.
	Author string
	// ProductID is an IRI/purl identifying the product these statements
	// describe, e.g. "pkg:generic/flatcar-container-linux@4593.2.4?channel=stable".
	// See docs/plan.md §9, Open Question #1 (product identifier scheme is
	// still provisional).
	ProductID string
	// Timestamp is when this document was generated. Defaults to time.Now()
	// if zero.
	Timestamp time.Time
	// Tooling optionally describes the tool and configuration that produced
	// the document, e.g. which vulnerability sources were consulted.
	Tooling string
}

// Build converts findings into an OpenVEX document with exactly one
// statement per CVE: a product can't be both fixed and affected by the same
// vulnerability, so emitting a statement per status would contradict
// itself. The statement's status is the most severe status among the CVE's
// findings (see match.StatusPrecedence), and its subcomponents are the packages
// that have that status.
func Build(findings []match.Finding, meta Metadata) (*vex.VEX, error) {
	if meta.ProductID == "" {
		return nil, fmt.Errorf("vexgen: Metadata.ProductID must not be empty")
	}

	doc := vex.New()
	if meta.Author != "" {
		doc.Author = meta.Author
	}
	doc.Tooling = meta.Tooling
	ts := meta.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	doc.Timestamp = &ts

	byCVE := map[string]map[match.Status][]match.Finding{}
	for _, f := range findings {
		if byCVE[f.CVE] == nil {
			byCVE[f.CVE] = map[match.Status][]match.Finding{}
		}
		byCVE[f.CVE][f.Status] = append(byCVE[f.CVE][f.Status], f)
	}

	cves := make([]string, 0, len(byCVE))
	for cve := range byCVE {
		cves = append(cves, cve)
	}
	sort.Strings(cves)

	for _, cve := range cves {
		var status match.Status
		var group []match.Finding
		for _, s := range match.StatusPrecedence {
			if g := byCVE[cve][s]; len(g) > 0 {
				status, group = s, g
				break
			}
		}
		if group == nil {
			return nil, fmt.Errorf("vexgen: %s has findings with unknown status", cve)
		}

		stmt := vex.Statement{
			Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(cve)},
			Timestamp:     &ts,
			Status:        vex.Status(status),
			StatusNotes:   statusNotes(group),
			Products: []vex.Product{
				{
					Component:     vex.Component{ID: meta.ProductID},
					Subcomponents: subcomponents(group),
				},
			},
		}

		switch status {
		case match.StatusAffected:
			stmt.ActionStatement = actionStatement(group)
		case match.StatusNotAffected:
			stmt.Justification = vex.VulnerableCodeNotPresent
			stmt.ImpactStatement = "The installed version is outside every vulnerable version range listed by the advisory."
		}

		doc.Statements = append(doc.Statements, stmt)
	}

	if _, err := doc.GenerateCanonicalID(); err != nil {
		return nil, fmt.Errorf("vexgen: generating document ID: %w", err)
	}

	return &doc, nil
}

// statusNotes joins the distinct, non-empty Finding.Note values of
// findings, so e.g. the reason for under_investigation reaches the VEX
// document.
func statusNotes(findings []match.Finding) string {
	seen := map[string]bool{}
	var notes []string
	for _, f := range findings {
		if f.Note != "" && !seen[f.Note] {
			seen[f.Note] = true
			notes = append(notes, f.Note)
		}
	}
	sort.Strings(notes)
	return strings.Join(notes, "; ")
}

// subcomponents builds the deduplicated, sorted list of package
// subcomponents for a group of findings that share a CVE and status.
func subcomponents(findings []match.Finding) []vex.Subcomponent {
	seen := map[string]bool{}
	var subs []vex.Subcomponent
	for _, f := range findings {
		if seen[f.Package.PURL] {
			continue
		}
		seen[f.Package.PURL] = true
		subs = append(subs, vex.Subcomponent{
			Component: vex.Component{
				Identifiers: map[vex.IdentifierType]string{vex.PURL: f.Package.PURL},
			},
		})
	}
	sort.Slice(subs, func(i, j int) bool {
		return subs[i].Identifiers[vex.PURL] < subs[j].Identifiers[vex.PURL]
	})
	return subs
}

// actionStatement produces a human-readable remediation note referencing the
// source advisories (GLSA IDs, OSV.dev IDs, ...) that flagged the affected
// packages in this group, grouped by source so mixed-source groups (e.g. the
// same CVE flagged by both GLSA and OSV.dev) read clearly rather than as one
// undifferentiated ID list.
func actionStatement(findings []match.Finding) string {
	refsBySource := map[string]map[string]bool{}
	for _, f := range findings {
		if f.RefID == "" {
			continue
		}
		refs := refsBySource[f.Source]
		if refs == nil {
			refs = map[string]bool{}
			refsBySource[f.Source] = refs
		}
		refs[f.RefID] = true
	}

	sources := make([]string, 0, len(refsBySource))
	for s := range refsBySource {
		sources = append(sources, s)
	}
	sort.Slice(sources, func(i, j int) bool {
		ri, rj := sourceOrder(sources[i]), sourceOrder(sources[j])
		if ri != rj {
			return ri < rj
		}
		return sources[i] < sources[j]
	})

	var parts []string
	for _, source := range sources {
		refs := make([]string, 0, len(refsBySource[source]))
		for id := range refsBySource[source] {
			refs = append(refs, id)
		}
		sort.Strings(refs)
		parts = append(parts, fmt.Sprintf("%s %s", sourceLabel(source), strings.Join(refs, ", ")))
	}

	msg := "Update the affected package(s) to a version that resolves this " + vulnLabel(findings)
	if len(parts) > 0 {
		msg += fmt.Sprintf(" (see %s)", strings.Join(parts, "; "))
	}
	return msg + "."
}

// vulnLabel returns "CVE" when findings' shared identifier (see
// Finding.CVE) is actually CVE-formatted, or the more accurate generic
// "vulnerability" otherwise. OSV.dev findings can carry a non-CVE
// identifier (e.g. a GHSA or GO ID, see osv.Vulnerability.CVEs) when the
// underlying advisory hasn't been assigned a CVE number, in which case
// "resolves this CVE" would be misleading.
func vulnLabel(findings []match.Finding) string {
	if len(findings) > 0 && strings.HasPrefix(findings[0].CVE, "CVE-") {
		return "CVE"
	}
	return "vulnerability"
}

// sourceOrder fixes a stable, human-sensible ordering for known sources in
// actionStatement's output; unrecognized sources sort after all known ones
// (alphabetically among themselves, via the caller's secondary sort key).
func sourceOrder(source string) int {
	switch source {
	case match.SourceGLSA:
		return 0
	case match.SourceOSV:
		return 1
	default:
		return 2
	}
}

// sourceLabel returns the human-readable prefix used for a source's
// advisory IDs in actionStatement, e.g. "Gentoo GLSA 202604-03".
func sourceLabel(source string) string {
	switch source {
	case match.SourceGLSA:
		return "Gentoo GLSA"
	case match.SourceOSV:
		return "OSV.dev advisory"
	default:
		return source
	}
}
