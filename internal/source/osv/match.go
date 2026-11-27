package osv

import (
	"context"
	"slices"
	"strings"

	"github.com/flatcar/vex-automation/internal/sbom"
	"github.com/flatcar/vex-automation/internal/vuln"
)

// osvEcosystems maps SBOM ecosystems to OSV.dev's names for them.
var osvEcosystems = map[sbom.Ecosystem]string{
	sbom.Golang: "Go",
	sbom.Cargo:  "crates.io",
}

// Match asks OSV.dev about every golang/cargo module (sbom.Document.Modules).
// OSV.dev only returns vulnerabilities that affect the exact version asked about, so
// every finding is affected. A fixed vulnerability therefore produces no
// finding at all; package diff treats that silence as a fix.
func Match(ctx context.Context, pkgs []sbom.Package, client *Client) ([]vuln.Finding, error) {
	queries := make([]Package, len(pkgs))
	for i, pkg := range pkgs {
		queries[i] = Package{Ecosystem: osvEcosystems[pkg.Ecosystem], Name: pkg.Name, Version: pkg.Version}
	}
	results, err := client.Query(ctx, queries)
	if err != nil {
		return nil, err
	}

	reportedIDs := reportedIDsByRecord(results)
	var findings []vuln.Finding
	for i, pkg := range pkgs {
		// One finding per reported ID, referencing the smallest record behind it.
		refByID := map[string]string{}
		// queries[i] is pkgs[i] as OSV.dev names it, the key of its results.
		for _, record := range results[queries[i]] {
			for _, id := range reportedIDs[record.ID] {
				if ref, seen := refByID[id]; !seen || record.ID < ref {
					refByID[id] = record.ID
				}
			}
		}
		for id, ref := range refByID {
			findings = append(findings, vuln.Finding{CVE: id, Source: vuln.SourceOSV, RefID: ref, Package: pkg, Status: vuln.StatusAffected})
		}
	}
	vuln.Sort(findings)
	return findings, nil
}

// reportedIDsByRecord maps each OSV.dev record ID to the IDs its findings
// are reported under.
//
// This matters because findings are grouped by ID later: reporting OSV.dev
// findings under their CVEs puts them in the same VEX statement (or diff
// entry) as GLSA findings for that CVE, instead of a second one under a
// GHSA or GO ID.
//
// Records linked by aliases (e.g. a GHSA and its GO record) describe one
// vulnerability. Each such group is reported under all of its CVEs, or
// under its smallest record ID if it has none. Groups are built across all
// packages, so the IDs stay the same when one version returns several
// records of a group and another version only one.
func reportedIDsByRecord(results map[Package][]Vulnerability) map[string][]string {
	links := map[string][]string{}
	isRecord := map[string]bool{}
	for _, records := range results {
		for _, record := range records {
			isRecord[record.ID] = true
			for _, alias := range record.Aliases {
				links[record.ID] = append(links[record.ID], alias)
				links[alias] = append(links[alias], record.ID)
			}
		}
	}

	reported := map[string][]string{}
	for id := range isRecord {
		if _, done := reported[id]; done {
			continue
		}
		group := linkedIDs(id, links)
		ids := groupIDs(group, isRecord)
		for _, member := range group {
			reported[member] = ids
		}
	}
	return reported
}

// linkedIDs returns start and every ID reachable from it through links.
func linkedIDs(start string, links map[string][]string) []string {
	seen := map[string]bool{start: true}
	group := []string{start}
	for i := 0; i < len(group); i++ {
		for _, next := range links[group[i]] {
			if !seen[next] {
				seen[next] = true
				group = append(group, next)
			}
		}
	}
	return group
}

// groupIDs returns the sorted CVEs of a group, or else its smallest record ID.
func groupIDs(group []string, isRecord map[string]bool) []string {
	var cves, records []string
	for _, id := range group {
		if strings.HasPrefix(id, "CVE-") {
			cves = append(cves, id)
		}
		if isRecord[id] {
			records = append(records, id)
		}
	}
	if len(cves) > 0 {
		slices.Sort(cves)
		return cves
	}
	return []string{slices.Min(records)}
}
