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
}

// Build converts findings into an OpenVEX document. Findings are grouped by
// (CVE, status) so that each resulting statement lists every affected
// package as a subcomponent, per OpenVEX convention, rather than emitting
// one statement per package.
func Build(findings []match.Finding, meta Metadata) (*vex.VEX, error) {
	if meta.ProductID == "" {
		return nil, fmt.Errorf("vexgen: Metadata.ProductID must not be empty")
	}

	doc := vex.New()
	if meta.Author != "" {
		doc.Author = meta.Author
	}
	ts := meta.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	doc.Timestamp = &ts

	type groupKey struct {
		cve      string
		affected bool
	}
	groups := map[groupKey][]match.Finding{}
	for _, f := range findings {
		key := groupKey{cve: f.CVE, affected: f.Affected}
		groups[key] = append(groups[key], f)
	}

	keys := make([]groupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].cve != keys[j].cve {
			return keys[i].cve < keys[j].cve
		}
		return !keys[i].affected && keys[j].affected // "not affected"/"fixed" before "affected", stable per CVE
	})

	for _, key := range keys {
		group := groups[key]

		status := vex.StatusFixed
		if key.affected {
			status = vex.StatusAffected
		}

		stmt := vex.Statement{
			Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(key.cve)},
			Timestamp:     &ts,
			Status:        status,
			Products: []vex.Product{
				{
					Component:     vex.Component{ID: meta.ProductID},
					Subcomponents: subcomponents(group),
				},
			},
		}

		if key.affected {
			stmt.ActionStatement = actionStatement(group)
		}

		doc.Statements = append(doc.Statements, stmt)
	}

	if _, err := doc.GenerateCanonicalID(); err != nil {
		return nil, fmt.Errorf("vexgen: generating document ID: %w", err)
	}

	return &doc, nil
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
// identifier (e.g. a GHSA or GO ID, see osv.Vulnerability.CVE) when the
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
