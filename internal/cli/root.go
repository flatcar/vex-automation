// Package cli implements the flatcar-vex commands (sync-glsa, generate and
// diff). It is the only package that ties the others together, so start
// reading here. README.md in this directory explains the flow, and
// internal/README.md the design.
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
