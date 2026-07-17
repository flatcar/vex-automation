// Package cli implements the flatcar-vex CLI commands.
package cli

import "github.com/spf13/cobra"

// Version is set at build time via -ldflags.
var Version = "dev"

// NewRootCmd builds the root cobra command for flatcar-vex.
//
// This is currently a scaffold: no VEX-generation logic has been implemented
// yet. Subcommands (bootstrap, update, match, ...) will be added here as the
// PoC described in docs/plan.md is built out.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flatcar-vex",
		Short: "Generate and maintain OpenVEX documents for Flatcar Container Linux releases",
		Long: `flatcar-vex generates machine-readable OpenVEX documents for Flatcar
Container Linux releases, derived only from data Flatcar already publishes
(release SBOMs and the Gentoo GLSA corpus).

See docs/plan.md in this repository for the full design and current status.`,
		Version: Version,

		// We print the error ourselves in main.go, so silence cobra's
		// default duplicate stderr output.
		SilenceErrors: true,
	}

	// Subcommands are added here as they are implemented.

	return cmd
}
