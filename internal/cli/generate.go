package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/flatcar/vex-automation/internal/match"
	"github.com/flatcar/vex-automation/internal/osv"
	"github.com/flatcar/vex-automation/internal/sbom"
	"github.com/flatcar/vex-automation/internal/vexgen"
)

type generateOptions struct {
	sharedOptions
	sbomPath  string
	productID string
	author    string
}

func newGenerateCmd() *cobra.Command {
	var opts generateOptions
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate an OpenVEX document from a local SBOM and a local GLSA directory",
		Long: `generate reads a Flatcar SPDX SBOM file and a local directory of Gentoo
GLSA XML advisories, matches every ebuild package in the SBOM against every
advisory, and writes an OpenVEX document with one statement per CVE (affected,
fixed, not_affected or under_investigation) for this release.

It also queries OSV.dev (https://osv.dev) for every golang/cargo package in
the SBOM, which the GLSA corpus doesn't cover, and merges those findings into
the same document. This requires network access. Pass --osv=false to work
offline; the document's "tooling" field then records that golang/cargo
packages were not checked. Likewise, when --allow-glsa-errors skips
unparseable advisories, "tooling" records how many were skipped.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGenerate(cmd, opts)
		},
	}
	opts.addFlags(cmd)
	cmd.Flags().StringVar(&opts.sbomPath, "sbom", "", "path to a local SPDX SBOM JSON file (required)")
	cmd.Flags().StringVar(&opts.productID, "product-id", "", "product identifier for the VEX document (default: derived from the SBOM's document name)")
	cmd.Flags().StringVar(&opts.author, "author", "", "author field for the VEX document")
	_ = cmd.MarkFlagRequired("sbom")
	return cmd
}

// runGenerate reads one SBOM, matches its packages against both
// vulnerability sources and writes the findings as an OpenVEX document
// (see the package documentation for the steps).
func runGenerate(cmd *cobra.Command, opts generateOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	doc, err := sbom.Load(opts.sbomPath)
	if err != nil {
		return err
	}
	logSkipped(doc.Skipped)
	if !opts.osvEnabled && len(doc.Packages) == 0 {
		return fmt.Errorf("SBOM %s has no ebuild package to match against GLSAs, and OSV.dev matching is disabled (--osv=false): nothing would be checked", opts.sbomPath)
	}

	glsas, skippedGLSAs, err := opts.loadGLSAs()
	if err != nil {
		return err
	}
	productID := opts.productID
	if productID == "" {
		if productID, err = deriveProductID(doc.Name); err != nil {
			return err
		}
	}

	// Both matchers return findings in the same form, so the document can
	// be built from one combined list.
	findings := match.RunGLSA(doc.Packages, glsas, opts.arch)
	if opts.osvEnabled {
		osvFindings, err := matchOSV(cmd, doc.OSVPackages, opts.osvBaseURL, opts.osvTimeout)
		if err != nil {
			return fmt.Errorf("matching against OSV.dev: %w", err)
		}
		findings = append(findings, osvFindings...)
	} else if len(doc.OSVPackages) > 0 {
		slog.Warn("OSV.dev matching disabled (--osv=false): golang/cargo packages are not checked for vulnerabilities",
			"packages", len(doc.OSVPackages))
	}

	vexDoc, err := vexgen.Build(findings, vexgen.Metadata{
		Author:    opts.author,
		ProductID: productID,
		Tooling:   opts.tooling("generate", skippedGLSAs),
	})
	if err != nil {
		return err
	}
	return writeJSON(cmd, opts.outPath, vexDoc)
}

// matchOSV matches pkgs against OSV.dev, giving up after timeout.
func matchOSV(cmd *cobra.Command, pkgs []sbom.Package, baseURL string, timeout time.Duration) ([]match.Finding, error) {
	ctx, cancel := withTimeout(cmd.Context(), timeout)
	defer cancel()
	return match.RunOSV(ctx, pkgs, &osv.Client{BaseURL: baseURL})
}

// writeJSON writes value as indented JSON to path, or to stdout.
func writeJSON(cmd *cobra.Command, path string, value any) error {
	out, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding output as JSON: %w", err)
	}
	return writeOutput(cmd, path, append(out, '\n'))
}

// releaseName matches the part of an SBOM name that names the release:
// "<group>-<version>", e.g. "stable-4593.2.4-a1" or
// "developer-4628.0.0+nightly-20260101-2100-a1".
var releaseName = regexp.MustCompile(`^([a-z][a-z0-9_]*)-([0-9][^/]*)$`)

// deriveProductID builds the product ID from the last path segment of the
// SBOM name that names a release. The product ID is what every VEX
// statement applies to, so consumers use it to tell which release a
// document is about. It fails rather than returning an ID
// without a version, which would give different builds the same identity.
// The ID scheme is provisional (docs/plan.md, open question 1).
func deriveProductID(sbomName string) (string, error) {
	segments := strings.Split(sbomName, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		if groups := releaseName.FindStringSubmatch(segments[i]); groups != nil {
			channel, version := groups[1], strings.ReplaceAll(groups[2], "+", "%2B")
			return fmt.Sprintf("pkg:generic/flatcar-container-linux@%s?channel=%s", version, channel), nil
		}
	}
	return "", fmt.Errorf("cannot derive a product ID from SBOM document name %q; pass --product-id", sbomName)
}
