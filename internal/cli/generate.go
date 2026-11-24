package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/flatcar/vex-automation/internal/glsa"
	"github.com/flatcar/vex-automation/internal/match"
	"github.com/flatcar/vex-automation/internal/osv"
	"github.com/flatcar/vex-automation/internal/sbom"
	"github.com/flatcar/vex-automation/internal/vexgen"
)

// releaseNamePattern extracts a Flatcar group+version from one path
// segment of an SBOM document's "name" field, e.g. "stable-4593.2.4-a1" ->
// channel="stable", version="4593.2.4-a1". Any lowercase group name is
// accepted, not only the release channels, so developer/nightly builds
// (e.g. "developer-4628.0.0+nightly-20260101-2100-a1") keep their version.
var releaseNamePattern = regexp.MustCompile(`^([a-z][a-z0-9_]*)-([0-9][^/]*)$`)

// defaultOSVTimeout bounds how long OSV.dev matching may take, mirroring
// sync-glsa's DefaultTimeout convention: a network problem should fail fast
// rather than hang forever.
const defaultOSVTimeout = 5 * time.Minute

// newGenerateCmd builds the "generate" subcommand: the most basic form of
// flatcar-vex, taking a local SBOM file and a local GLSA directory and
// producing an OpenVEX document.
func newGenerateCmd() *cobra.Command {
	var (
		sbomPath        string
		glsaDir         string
		outPath         string
		arch            string
		productID       string
		author          string
		osvEnabled      bool
		osvBaseURL      string
		osvTimeout      time.Duration
		allowGLSAErrors bool
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate an OpenVEX document from a local SBOM and a local GLSA directory",
		Long: `generate reads a Flatcar SPDX SBOM file and a local directory of Gentoo
GLSA XML advisories, matches every ebuild package in the SBOM against every
advisory, and writes an OpenVEX document with one statement per CVE (affected,
fixed, not_affected or under_investigation) for this release.

It also queries OSV.dev (https://osv.dev) for every golang/cargo package in
the SBOM (the packages the GLSA corpus has no coverage for at all) and merges
those findings into the same document. This requires network access; unlike
GLSA there is no local corpus to sync first (see
docs/multi-source-proposal.md for why OSV.dev's API doesn't need one). Pass
--osv=false to work offline; the document's "tooling" field then records
that golang/cargo packages were not checked.

This is the most basic PoC form described in docs/plan.md: no caching or
rolling-forward logic is included here, only the core match and generate
step.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGenerate(cmd, generateOptions{
				sbomPath:   sbomPath,
				glsaDir:    glsaDir,
				outPath:    outPath,
				arch:       arch,
				productID:  productID,
				author:     author,
				osvEnabled: osvEnabled,
				osvBaseURL: osvBaseURL,
				osvTimeout: osvTimeout,

				allowGLSAErrors: allowGLSAErrors,
			})
		},
	}

	cmd.Flags().StringVar(&sbomPath, "sbom", "", "path to a local SPDX SBOM JSON file (required)")
	cmd.Flags().StringVar(&glsaDir, "glsa-dir", "", "path to a local directory containing GLSA *.xml files (required)")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "output file path (default: stdout)")
	cmd.Flags().StringVar(&arch, "arch", "amd64", "architecture to match GLSA entries against")
	cmd.Flags().StringVar(&productID, "product-id", "", "product identifier for the VEX document (default: derived from the SBOM's document name)")
	cmd.Flags().StringVar(&author, "author", "", "author field for the VEX document")
	cmd.Flags().BoolVar(&osvEnabled, "osv", true, "match golang/cargo SBOM packages against OSV.dev (requires network access; --osv=false leaves them unchecked)")
	cmd.Flags().StringVar(&osvBaseURL, "osv-base-url", osv.DefaultBaseURL, "OSV.dev API base URL (override for testing or a private mirror)")
	cmd.Flags().DurationVar(&osvTimeout, "osv-timeout", defaultOSVTimeout, "maximum time to allow OSV.dev matching to run")
	cmd.Flags().BoolVar(&allowGLSAErrors, "allow-glsa-errors", false, "continue with the remaining advisories when some GLSA files fail to parse, instead of failing")

	_ = cmd.MarkFlagRequired("sbom")
	_ = cmd.MarkFlagRequired("glsa-dir")

	return cmd
}

type generateOptions struct {
	sbomPath   string
	glsaDir    string
	outPath    string
	arch       string
	productID  string
	author     string
	osvEnabled bool
	osvBaseURL string
	osvTimeout time.Duration

	allowGLSAErrors bool
}

func runGenerate(cmd *cobra.Command, opts generateOptions) error {
	doc, err := sbom.Load(opts.sbomPath)
	if err != nil {
		return err
	}
	logSkipped(doc.Skipped)

	glsas, err := glsa.LoadDir(opts.glsaDir)
	var parseErr *glsa.ParseError
	switch {
	case errors.As(err, &parseErr) && opts.allowGLSAErrors && len(glsas) > 0:
		for _, e := range parseErr.Errs {
			slog.Warn("skipping unparseable GLSA file", "error", e)
		}
	case err != nil:
		switch {
		case parseErr != nil && opts.allowGLSAErrors:
			return fmt.Errorf("no GLSA file in %s could be parsed: %w", opts.glsaDir, err)
		case parseErr != nil:
			return fmt.Errorf("%w (pass --allow-glsa-errors to continue without them)", err)
		}
		return err
	}

	productID := opts.productID
	if productID == "" {
		productID, err = deriveProductID(doc.Name)
		if err != nil {
			return err
		}
	}

	findings := match.Run(doc.Packages, glsas, opts.arch)

	tooling := "flatcar-vex generate (sources: Gentoo GLSA, OSV.dev)"
	if !opts.osvEnabled {
		tooling = "flatcar-vex generate (sources: Gentoo GLSA only; OSV.dev disabled, golang/cargo packages not checked)"
		if len(doc.OSVPackages) > 0 {
			slog.Warn("OSV.dev matching disabled (--osv=false): golang/cargo packages are not checked for vulnerabilities",
				"packages", len(doc.OSVPackages))
		}
	} else {
		if opts.osvTimeout < 0 {
			return fmt.Errorf("--osv-timeout must be >= 0 unless --osv=false")
		}
		if opts.osvBaseURL == "" {
			return fmt.Errorf("--osv-base-url must not be empty unless --osv=false")
		}
		osvFindings, err := matchOSV(cmd, doc, opts)
		if err != nil {
			return fmt.Errorf("matching against OSV.dev: %w", err)
		}
		findings = append(findings, osvFindings...)
	}

	vexDoc, err := vexgen.Build(findings, vexgen.Metadata{
		Author:    opts.author,
		ProductID: productID,
		Tooling:   tooling,
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

// matchOSV runs match.RunOSV against doc's golang/cargo packages, bounding
// the call with opts.osvTimeout. context.WithTimeout automatically keeps
// the earliest of the parent's existing deadline (if any) and this one, so
// the flag stays effective even when cmd's context already carries its own
// (possibly looser) deadline.
func matchOSV(cmd *cobra.Command, doc sbom.Document, opts generateOptions) ([]match.Finding, error) {
	ctx := cmd.Context()
	if opts.osvTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.osvTimeout)
		defer cancel()
	}

	client := &osv.Client{BaseURL: opts.osvBaseURL}
	return match.RunOSV(ctx, doc.OSVPackages, client)
}

// logSkipped summarizes, per reason, the SBOM packages that no
// vulnerability source covers, so the coverage gap is visible.
func logSkipped(skipped []sbom.SkippedPackage) {
	byReason := map[string][]string{}
	for _, sk := range skipped {
		byReason[sk.Reason] = append(byReason[sk.Reason], sk.Name)
	}
	reasons := make([]string, 0, len(byReason))
	for r := range byReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		names := byReason[r]
		sort.Strings(names)
		slog.Info("SBOM packages not matched against any vulnerability source",
			"reason", r, "count", len(names), "packages", strings.Join(names, ","))
	}
}

// deriveProductID builds a best-effort product identifier from an SBOM
// document's "name" field, taken from the last path segment of the form
// "<group>-<version>". See docs/plan.md §9, Open Question #1: the product
// identifier scheme is still provisional; this is a placeholder good enough
// for the PoC. It fails rather than falling back to a versionless ID, since
// that would give documents for different builds the same product identity.
func deriveProductID(sbomDocName string) (string, error) {
	segments := strings.Split(sbomDocName, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		m := releaseNamePattern.FindStringSubmatch(segments[i])
		if m == nil {
			continue
		}
		channel, version := m[1], strings.ReplaceAll(m[2], "+", "%2B")
		return fmt.Sprintf("pkg:generic/flatcar-container-linux@%s?channel=%s", version, channel), nil
	}
	return "", fmt.Errorf("cannot derive a product ID from SBOM document name %q; pass --product-id", sbomDocName)
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
