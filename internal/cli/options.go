package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/flatcar/vex-automation/internal/sbom"
	"github.com/flatcar/vex-automation/internal/source/glsa"
	"github.com/flatcar/vex-automation/internal/source/osv"
	"github.com/spf13/cobra"
)

// defaultOSVTimeout makes a network problem fail the run instead of
// hanging it.
const defaultOSVTimeout = 5 * time.Minute

// sharedOptions are the flags of both generate and diff.
type sharedOptions struct {
	glsaDir         string
	outPath         string
	arch            string
	osvEnabled      bool
	osvBaseURL      string
	osvTimeout      time.Duration
	allowGLSAErrors bool
}

func (o *sharedOptions) addFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&o.glsaDir, "glsa-dir", "", "path to a local directory containing GLSA *.xml files (required)")
	flags.StringVarP(&o.outPath, "output", "o", "", "output file path (default: stdout)")
	flags.StringVar(&o.arch, "arch", "amd64", "architecture to match GLSA entries against")
	flags.BoolVar(&o.osvEnabled, "osv", true, "match golang/cargo SBOM packages against OSV.dev (requires network access; --osv=false leaves them unchecked)")
	flags.StringVar(&o.osvBaseURL, "osv-base-url", osv.DefaultBaseURL, "OSV.dev API base URL (override for testing or a private mirror)")
	flags.DurationVar(&o.osvTimeout, "osv-timeout", defaultOSVTimeout, "maximum time to allow OSV.dev matching to run")
	flags.BoolVar(&o.allowGLSAErrors, "allow-glsa-errors", false, "continue with the remaining advisories when some GLSA files fail to parse, instead of failing")
	_ = cmd.MarkFlagRequired("glsa-dir")
}

func (o *sharedOptions) validate() error {
	if !o.osvEnabled {
		return nil
	}
	if o.osvTimeout < 0 {
		return errors.New("--osv-timeout must be >= 0 unless --osv=false")
	}
	if o.osvBaseURL == "" {
		return errors.New("--osv-base-url must not be empty unless --osv=false")
	}
	return nil
}

// loadGLSAs loads every advisory in --glsa-dir and returns how many files
// were skipped. Unparseable files fail the run, unless --allow-glsa-errors
// is set and at least one advisory could be parsed.
func (o *sharedOptions) loadGLSAs() ([]glsa.GLSA, int, error) {
	glsas, err := glsa.LoadDir(o.glsaDir)
	var parseErr *glsa.ParseError
	if !errors.As(err, &parseErr) {
		return glsas, 0, err
	}
	if !o.allowGLSAErrors {
		return nil, 0, fmt.Errorf("%w (pass --allow-glsa-errors to continue without them)", err)
	}
	if len(glsas) == 0 {
		return nil, 0, fmt.Errorf("no GLSA file in %s could be parsed: %w", o.glsaDir, err)
	}
	for _, fileErr := range parseErr.Errs {
		slog.Warn("skipping unparseable GLSA file", "error", fileErr)
	}
	return glsas, len(parseErr.Errs), nil
}

// tooling describes the sources behind the output, so that disabled
// OSV.dev matching or skipped GLSAs are visible in the output itself.
// Without it, a document made from partial data would look the same as
// a complete one.
func (o *sharedOptions) tooling(command string, skippedGLSAs int) string {
	sources := "Gentoo GLSA, OSV.dev"
	if !o.osvEnabled {
		sources = "Gentoo GLSA only; OSV.dev disabled, golang/cargo packages not checked"
	}
	if skippedGLSAs > 0 {
		sources += fmt.Sprintf("; incomplete GLSA corpus, unparseable files skipped: %d", skippedGLSAs)
	}
	return fmt.Sprintf("flatcar-vex %s (sources: %s)", command, sources)
}

// withTimeout limits ctx to timeout (0 means no limit).
func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return ctx, func() {}
}

// logSkipped logs, per reason, the SBOM packages that no vulnerability
// source covers.
func logSkipped(skipped []sbom.SkippedPackage) {
	namesByReason := map[string][]string{}
	for _, pkg := range skipped {
		namesByReason[pkg.Reason] = append(namesByReason[pkg.Reason], pkg.Name)
	}
	for _, reason := range slices.Sorted(maps.Keys(namesByReason)) {
		names := namesByReason[reason]
		slices.Sort(names)
		slog.Info("SBOM packages not matched against any vulnerability source",
			"reason", reason, "count", len(names), "packages", strings.Join(names, ","))
	}
}

// writeOutput writes data to path, or to stdout if path is empty.
func writeOutput(cmd *cobra.Command, path string, data []byte) error {
	if path == "" {
		_, err := cmd.OutOrStdout().Write(data)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // VEX output is not sensitive.
		return fmt.Errorf("writing output file %q: %w", path, err)
	}
	return nil
}
