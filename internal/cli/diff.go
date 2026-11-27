package cli

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/spf13/cobra"

	"github.com/flatcar/vex-automation/internal/diff"
	"github.com/flatcar/vex-automation/internal/match"
	"github.com/flatcar/vex-automation/internal/osv"
	"github.com/flatcar/vex-automation/internal/sbom"
)

type diffOptions struct {
	sharedOptions
	oldSBOM string
	newSBOM string
	format  string
}

func newDiffCmd() *cobra.Command {
	var opts diffOptions
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare the vulnerabilities of two releases' SBOMs",
		Long: `diff matches the SBOMs of two releases (an older and a newer one) against the
same vulnerability data (a local GLSA directory for ebuild packages, one
OSV.dev pass for golang/cargo packages) and reports, per (vulnerability,
package), whether the newer release fixed it, removed the package,
introduced it, is still affected, or needs review.

--format json (the default) writes every reported entry with its versions,
sources and advisories, plus what was not checked (e.g. the kernel).
--format changelog writes only the fixed entries as Markdown, in the style of
the "Security fixes" section of the Flatcar release notes. The result is a
draft for human review: it is a version match, not an exploitability
assessment, and GLSA advisories bundle many CVEs under one version range.

The command exits 0 whenever the diff could be computed, whatever it
contains.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDiff(cmd, opts)
		},
	}
	opts.addFlags(cmd)
	cmd.Flags().StringVar(&opts.oldSBOM, "old-sbom", "", "path to the SPDX SBOM JSON file of the previous release (required)")
	cmd.Flags().StringVar(&opts.newSBOM, "new-sbom", "", "path to the SPDX SBOM JSON file of the new release (required)")
	cmd.Flags().StringVar(&opts.format, "format", "json", "output format: json or changelog")
	_ = cmd.MarkFlagRequired("old-sbom")
	_ = cmd.MarkFlagRequired("new-sbom")
	return cmd
}

// runDiff matches two SBOMs against the same data and reports how each
// (vulnerability, package) pair changed between them (see the package
// documentation for the steps).
func runDiff(cmd *cobra.Command, opts diffOptions) error {
	if opts.format != "json" && opts.format != "changelog" {
		return fmt.Errorf("--format must be json or changelog, got %q", opts.format)
	}
	if err := opts.validate(); err != nil {
		return err
	}

	oldDoc, err := sbom.Load(opts.oldSBOM)
	if err != nil {
		return err
	}
	newDoc, err := sbom.Load(opts.newSBOM)
	if err != nil {
		return err
	}
	logSkipped(oldDoc.Skipped)
	logSkipped(newDoc.Skipped)

	glsas, skippedGLSAs, err := opts.loadGLSAs()
	if err != nil {
		return err
	}
	in := diff.Input{
		Old: diff.Side{Doc: oldDoc, Findings: match.RunGLSA(oldDoc.Packages, glsas, opts.arch)},
		New: diff.Side{Doc: newDoc, Findings: match.RunGLSA(newDoc.Packages, glsas, opts.arch)},
	}
	if opts.osvEnabled {
		if err := addOSVFindings(cmd.Context(), opts, &in); err != nil {
			return err
		}
	} else {
		slog.Warn("OSV.dev matching disabled (--osv=false): golang/cargo packages are not compared",
			"old_packages", len(oldDoc.OSVPackages), "new_packages", len(newDoc.OSVPackages))
		// Without findings, every golang/cargo package would look clean on
		// both sides, so leave them out of the diff entirely.
		in.Old.Doc.OSVPackages, in.New.Doc.OSVPackages = nil, nil
	}

	result := diff.Compute(in)
	result.Tooling = opts.tooling("diff", skippedGLSAs)
	result.Old = releaseOf(oldDoc)
	result.New = releaseOf(newDoc)
	result.NotChecked.OSVDisabled = !opts.osvEnabled
	slog.Info("diff computed", "fixed", result.Summary.Fixed, "removed", result.Summary.Removed,
		"introduced", result.Summary.Introduced, "still_affected", result.Summary.StillAffected, "review", result.Summary.Review)

	if opts.format == "changelog" {
		return writeOutput(cmd, opts.outPath, []byte(diff.FormatChangelog(result)))
	}
	return writeJSON(cmd, opts.outPath, result)
}

// addOSVFindings rechecks curl's GLSA findings and adds the OSV.dev
// findings of both sides. One timeout covers all of it.
//
// The curl recheck only runs here, not in generate: Gentoo's curl GLSAs
// bundle years of CVEs under one range, so without it the changelog would
// list CVEs as newly fixed that the previous release had fixed long ago.
// It needs OSV.dev, so it is skipped with --osv=false.
func addOSVFindings(ctx context.Context, opts diffOptions, in *diff.Input) error {
	ctx, cancel := withTimeout(ctx, opts.osvTimeout)
	defer cancel()
	client := &osv.Client{BaseURL: opts.osvBaseURL}

	if err := applyCurlAdvisories(ctx, client, in); err != nil {
		return fmt.Errorf("fetching curl advisories from OSV.dev: %w", err)
	}
	oldFindings, newFindings, err := matchOSVBothSides(ctx, client, in.Old.Doc.OSVPackages, in.New.Doc.OSVPackages)
	if err != nil {
		return fmt.Errorf("matching against OSV.dev: %w", err)
	}
	in.Old.Findings = append(in.Old.Findings, oldFindings...)
	in.New.Findings = append(in.New.Findings, newFindings...)
	return nil
}

// matchOSVBothSides queries OSV.dev once for the packages of both sides,
// so both are matched against the same OSV.dev data, then splits the
// findings back per side.
func matchOSVBothSides(ctx context.Context, client *osv.Client, oldPkgs, newPkgs []sbom.Package) (oldFindings, newFindings []match.Finding, err error) {
	inOld, inNew := toSet(oldPkgs), toSet(newPkgs)
	var bothSides []sbom.Package
	seen := map[sbom.Package]bool{}
	for _, pkg := range append(slices.Clone(oldPkgs), newPkgs...) {
		if !seen[pkg] {
			seen[pkg] = true
			bothSides = append(bothSides, pkg)
		}
	}
	findings, err := match.RunOSV(ctx, bothSides, client)
	if err != nil {
		return nil, nil, err
	}
	for _, finding := range findings {
		if inOld[finding.Package] {
			oldFindings = append(oldFindings, finding)
		}
		if inNew[finding.Package] {
			newFindings = append(newFindings, finding)
		}
	}
	return oldFindings, newFindings, nil
}

// applyCurlAdvisories rechecks the curl GLSA findings of both sides
// against curl's own advisories on OSV.dev (see match.ApplyCurlAdvisories).
func applyCurlAdvisories(ctx context.Context, client *osv.Client, in *diff.Input) error {
	ids := match.CurlAdvisoryIDs(append(slices.Clone(in.Old.Findings), in.New.Findings...))
	if len(ids) == 0 {
		return nil
	}
	advisories, err := client.Get(ctx, ids)
	if err != nil {
		return err
	}
	in.Old.Findings = match.ApplyCurlAdvisories(in.Old.Findings, advisories)
	in.New.Findings = match.ApplyCurlAdvisories(in.New.Findings, advisories)
	slog.Info("rechecked curl GLSA findings against curl's own advisories", "cves", len(ids), "advisories", len(advisories))
	return nil
}

// releaseOf describes one side of the diff. The product ID is left empty
// if it can't be derived, since the diff doesn't depend on it.
func releaseOf(doc sbom.Document) diff.Release {
	id, err := deriveProductID(doc.Name)
	if err != nil {
		slog.Warn("cannot derive a product ID for the diff output", "error", err)
	}
	return diff.Release{SBOMName: doc.Name, ProductID: id}
}

func toSet(pkgs []sbom.Package) map[sbom.Package]bool {
	set := make(map[sbom.Package]bool, len(pkgs))
	for _, pkg := range pkgs {
		set[pkg] = true
	}
	return set
}
