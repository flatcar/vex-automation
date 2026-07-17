package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/flatcar/vex-automation/internal/glsa"
	"github.com/flatcar/vex-automation/internal/match"
	"github.com/flatcar/vex-automation/internal/sbom"
	"github.com/flatcar/vex-automation/internal/vexgen"
)

// releaseNamePattern extracts a Flatcar channel+version from an SBOM
// document's "name" field, e.g.
// ".../amd64-usr/stable-4593.2.4-a1/rootfs-with-sysext-pkgs" ->
// channel="stable", version="4593.2.4-a1".
var releaseNamePattern = regexp.MustCompile(`(alpha|beta|stable|lts)-([0-9][^/]*)`)

// newGenerateCmd builds the "generate" subcommand: the most basic form of
// flatcar-vex, taking a local SBOM file and a local GLSA directory and
// producing an OpenVEX document.
func newGenerateCmd() *cobra.Command {
	var (
		sbomPath  string
		glsaDir   string
		outPath   string
		arch      string
		productID string
		author    string
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate an OpenVEX document from a local SBOM and a local GLSA directory",
		Long: `generate reads a Flatcar SPDX SBOM file and a local directory of Gentoo
GLSA XML advisories, matches every ebuild package in the SBOM against every
advisory, and writes an OpenVEX document describing which CVEs affect (or
have been fixed in) this release.

This is the most basic PoC form described in docs/plan.md: no fetching,
caching, or rolling-forward logic is included here, only the core match and
generate step.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGenerate(cmd, generateOptions{
				sbomPath:  sbomPath,
				glsaDir:   glsaDir,
				outPath:   outPath,
				arch:      arch,
				productID: productID,
				author:    author,
			})
		},
	}

	cmd.Flags().StringVar(&sbomPath, "sbom", "", "path to a local SPDX SBOM JSON file (required)")
	cmd.Flags().StringVar(&glsaDir, "glsa-dir", "", "path to a local directory containing GLSA *.xml files (required)")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "output file path (default: stdout)")
	cmd.Flags().StringVar(&arch, "arch", "amd64", "architecture to match GLSA entries against")
	cmd.Flags().StringVar(&productID, "product-id", "", "product identifier for the VEX document (default: derived from the SBOM's document name)")
	cmd.Flags().StringVar(&author, "author", "", "author field for the VEX document")

	_ = cmd.MarkFlagRequired("sbom")
	_ = cmd.MarkFlagRequired("glsa-dir")

	return cmd
}

type generateOptions struct {
	sbomPath  string
	glsaDir   string
	outPath   string
	arch      string
	productID string
	author    string
}

func runGenerate(cmd *cobra.Command, opts generateOptions) error {
	doc, err := sbom.LoadEbuildPackages(opts.sbomPath)
	if err != nil {
		return err
	}

	glsas, err := glsa.LoadDir(opts.glsaDir)
	if err != nil {
		return err
	}

	productID := opts.productID
	if productID == "" {
		productID = deriveProductID(doc.Name)
	}

	findings := match.Run(doc.Packages, glsas, opts.arch)

	vexDoc, err := vexgen.Build(findings, vexgen.Metadata{
		Author:    opts.author,
		ProductID: productID,
	})
	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(vexDoc, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding VEX document as JSON: %w", err)
	}
	out = append(out, '\n')

	return writeOutput(cmd, opts.outPath, out)
}

// deriveProductID builds a best-effort product identifier from an SBOM
// document's "name" field. See docs/plan.md §9, Open Question #1: the
// product identifier scheme is still provisional; this is a placeholder
// good enough for the PoC.
func deriveProductID(sbomDocName string) string {
	m := releaseNamePattern.FindStringSubmatch(sbomDocName)
	if m == nil {
		return "pkg:generic/flatcar-container-linux"
	}
	channel, version := m[1], m[2]
	return fmt.Sprintf("pkg:generic/flatcar-container-linux@%s?channel=%s", version, channel)
}

// writeOutput writes data to path, or to cmd's stdout if path is empty.
func writeOutput(cmd *cobra.Command, path string, data []byte) error {
	if path == "" {
		_, err := io.Copy(cmd.OutOrStdout(), bytes.NewReader(data))
		return err
	}

	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // VEX output is not sensitive.
		return fmt.Errorf("writing output file %q: %w", path, err)
	}
	return nil
}
