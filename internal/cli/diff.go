package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/flatcar/vex-automation/internal/diff"
	"github.com/flatcar/vex-automation/internal/match"
	"github.com/flatcar/vex-automation/internal/osv"
	"github.com/flatcar/vex-automation/internal/sbom"
)

type diffOptions struct {
	oldSBOM    string
	newSBOM    string
	glsaDir    string
	outPath    string
	arch       string
	format     string
	osvEnabled bool
	osvBaseURL string
	osvTimeout time.Duration

	allowGLSAErrors bool
}

// newDiffCmd builds the "diff" subcommand, which reports the
// vulnerabilities a release fixed (or introduced) compared to the previous
// one.
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

	cmd.Flags().StringVar(&opts.oldSBOM, "old-sbom", "", "path to the SPDX SBOM JSON file of the previous release (required)")
	cmd.Flags().StringVar(&opts.newSBOM, "new-sbom", "", "path to the SPDX SBOM JSON file of the new release (required)")
	cmd.Flags().StringVar(&opts.glsaDir, "glsa-dir", "", "path to a local directory containing GLSA *.xml files (required)")
	cmd.Flags().StringVarP(&opts.outPath, "output", "o", "", "output file path (default: stdout)")
	cmd.Flags().StringVar(&opts.arch, "arch", "amd64", "architecture to match GLSA entries against")
	cmd.Flags().StringVar(&opts.format, "format", "json", "output format: json or changelog")
	cmd.Flags().BoolVar(&opts.osvEnabled, "osv", true, "match golang/cargo SBOM packages against OSV.dev (requires network access; --osv=false leaves them unchecked)")
	cmd.Flags().StringVar(&opts.osvBaseURL, "osv-base-url", osv.DefaultBaseURL, "OSV.dev API base URL (override for testing or a private mirror)")
	cmd.Flags().DurationVar(&opts.osvTimeout, "osv-timeout", defaultOSVTimeout, "maximum time to allow OSV.dev matching to run")
	cmd.Flags().BoolVar(&opts.allowGLSAErrors, "allow-glsa-errors", false, "continue with the remaining advisories when some GLSA files fail to parse, instead of failing")

	_ = cmd.MarkFlagRequired("old-sbom")
	_ = cmd.MarkFlagRequired("new-sbom")
	_ = cmd.MarkFlagRequired("glsa-dir")

	return cmd
}

func runDiff(cmd *cobra.Command, opts diffOptions) error {
	if opts.format != "json" && opts.format != "changelog" {
		return fmt.Errorf("--format must be json or changelog, got %q", opts.format)
	}
	if opts.osvEnabled {
		if err := validateOSVFlags(opts.osvBaseURL, opts.osvTimeout); err != nil {
			return err
		}
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

	glsas, skippedGLSAs, err := loadGLSAs(opts.glsaDir, opts.allowGLSAErrors)
	if err != nil {
		return err
	}

	in := diff.Input{
		Old: diff.Side{Doc: oldDoc, Findings: match.Run(oldDoc.Packages, glsas, opts.arch)},
		New: diff.Side{Doc: newDoc, Findings: match.Run(newDoc.Packages, glsas, opts.arch)},
	}

	if opts.osvEnabled {
		// One deadline for all OSV.dev work, so --osv-timeout bounds the
		// whole run rather than each stage.
		ctx, cancel := withOSVTimeout(cmd.Context(), opts.osvTimeout)
		defer cancel()
		client := &osv.Client{BaseURL: opts.osvBaseURL}
		if err := applyCurlAdvisories(ctx, client, &in); err != nil {
			return fmt.Errorf("fetching curl advisories from OSV.dev: %w", err)
		}
		oldOSV, newOSV, err := matchOSVBothSides(ctx, client, oldDoc.OSVPackages, newDoc.OSVPackages)
		if err != nil {
			return fmt.Errorf("matching against OSV.dev: %w", err)
		}
		in.Old.Findings = append(in.Old.Findings, oldOSV...)
		in.New.Findings = append(in.New.Findings, newOSV...)
	} else {
		slog.Warn("OSV.dev matching disabled (--osv=false): golang/cargo packages are not compared",
			"old_packages", len(oldDoc.OSVPackages), "new_packages", len(newDoc.OSVPackages))
		// Without findings every golang/cargo package would look clean on
		// both sides; drop them so they can't produce entries at all.
		in.Old.Doc.OSVPackages, in.New.Doc.OSVPackages = nil, nil
	}

	res := diff.Compute(in)
	res.Tooling = toolingOf("diff", opts.osvEnabled, skippedGLSAs)
	res.Old = releaseOf(oldDoc)
	res.New = releaseOf(newDoc)
	res.NotChecked.OSVDisabled = !opts.osvEnabled
	slog.Info("diff computed", "fixed", res.Summary.Fixed, "removed", res.Summary.Removed,
		"introduced", res.Summary.Introduced, "still_affected", res.Summary.StillAffected, "review", res.Summary.Review)

	var out []byte
	switch opts.format {
	case "changelog":
		out = []byte(diff.FormatChangelog(res))
	default:
		out, err = json.MarshalIndent(res, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding diff as JSON: %w", err)
		}
		out = append(out, '\n')
	}
	return writeOutput(cmd, opts.outPath, out)
}

// matchOSVBothSides queries OSV.dev once for the union of both sides'
// packages, so that both are matched against the same snapshot of OSV.dev
// data, and splits the findings back per side.
func matchOSVBothSides(ctx context.Context, client *osv.Client, oldPkgs, newPkgs []sbom.Package) (oldFindings, newFindings []match.Finding, err error) {
	inOld, inNew := map[sbom.Package]bool{}, map[sbom.Package]bool{}
	var union []sbom.Package
	add := func(pkgs []sbom.Package, side map[sbom.Package]bool) {
		for _, p := range pkgs {
			if !inOld[p] && !inNew[p] {
				union = append(union, p)
			}
			side[p] = true
		}
	}
	add(oldPkgs, inOld)
	add(newPkgs, inNew)

	findings, err := match.RunOSV(ctx, union, client)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range findings {
		if inOld[f.Package] {
			oldFindings = append(oldFindings, f)
		}
		if inNew[f.Package] {
			newFindings = append(newFindings, f)
		}
	}
	return oldFindings, newFindings, nil
}

// applyCurlAdvisories rechecks both sides' GLSA findings for curl against
// curl's own advisories on OSV.dev (see match.ApplyCurlAdvisories), so CVEs
// fixed upstream long before the older release don't show up as fixed now.
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

// releaseOf describes one side of the diff. A product ID that can't be
// derived is left empty: the diff doesn't need it to be correct.
func releaseOf(doc sbom.Document) diff.Release {
	id, err := deriveProductID(doc.Name)
	if err != nil {
		slog.Warn("cannot derive a product ID for the diff output", "error", err)
		id = ""
	}
	return diff.Release{SBOMName: doc.Name, ProductID: id}
}
