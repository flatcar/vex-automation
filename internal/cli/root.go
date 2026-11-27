// Package cli implements the flatcar-vex commands. It is the only package
// that ties the others together, so it is the place to start reading.
// docs/architecture.md explains the same flow and the reasons behind it.
//
// generate answers "which known vulnerabilities affect this release?":
//
//	sbom.Load       read the release's SBOM and sort its packages by the
//	                source that can check them
//	glsa.LoadDir    read Gentoo's advisories (downloaded by sync-glsa)
//	match.RunGLSA   check ebuild packages against the GLSA version ranges
//	match.RunOSV    check golang/cargo packages against OSV.dev (network)
//	vexgen.Build    write one OpenVEX statement per vulnerability
//
// diff answers "what did the newer release fix?", to draft the release
// notes. It loads and matches two SBOMs the same way, against the same
// advisories, so that any change in the result comes from the releases
// and not from the data. Then:
//
//	match.ApplyCurlAdvisories  correct curl's GLSA findings (too coarse)
//	diff.Compute               classify each (vulnerability, package) pair
//	diff.FormatChangelog       optionally render the fixed ones as Markdown
//
// sync-glsa (glsasync.Sync) clones or updates the advisory directory that
// generate and diff read with --glsa-dir.
//
// All steps share one rule: something that wasn't checked must not look
// like "not affected". A version that can't be evaluated becomes
// under_investigation. The "tooling" field of the OpenVEX document and of
// the diff JSON records when OSV.dev was off or GLSA files didn't parse.
// The diff JSON also lists packages no source covers under "not_checked";
// generate only logs them (visible with --verbose). The changelog is plain
// release-notes text and carries none of this.
package cli

import (
	"log/slog"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// NewRootCmd builds the flatcar-vex command and its subcommands.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flatcar-vex",
		Short: "Generate and maintain OpenVEX documents for Flatcar Container Linux releases",
		Long: `flatcar-vex generates machine-readable OpenVEX documents for Flatcar
Container Linux releases, by matching release SBOMs against the Gentoo GLSA
corpus (ebuild packages, using only data Flatcar and Gentoo already publish)
and OSV.dev's public API (golang/cargo packages; requires live network
access, disable with "generate --osv=false"). "diff" compares two releases
and drafts the "Security fixes" section of the release notes.

See docs/plan.md in this repository for the full design and current status.`,
		Version: Version,
		// main.go prints the error itself.
		SilenceErrors: true,
	}

	var verbose bool
	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "also log informational messages (default: warnings and errors only)")
	cmd.PersistentPreRun = func(*cobra.Command, []string) {
		if verbose {
			slog.SetLogLoggerLevel(slog.LevelInfo)
		} else {
			slog.SetLogLoggerLevel(slog.LevelWarn)
		}
	}

	cmd.AddCommand(newGenerateCmd(), newDiffCmd(), newSyncGLSACmd())
	return cmd
}
