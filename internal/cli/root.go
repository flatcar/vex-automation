// Package cli implements the flatcar-vex CLI commands.
package cli

import "github.com/spf13/cobra"

// Version is set at build time via -ldflags.
var Version = "dev"

// NewRootCmd builds the root cobra command for flatcar-vex.
//
// The "generate" subcommand implements the basic PoC pipeline described in
// docs/plan.md (SBOM + local GLSA directory -> OpenVEX document). Further
// subcommands (e.g. fetching inputs automatically, rolling forward across
// releases) will be added here as later phases are built out.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flatcar-vex",
		Short: "Generate and maintain OpenVEX documents for Flatcar Container Linux releases",
		Long: `flatcar-vex generates machine-readable OpenVEX documents for Flatcar
Container Linux releases, by matching release SBOMs against the Gentoo GLSA
corpus (ebuild packages, using only data Flatcar and Gentoo already publish)
and, optionally, OSV.dev's public API (golang/cargo packages; requires live
network access to an external data source, see "generate --help").

See docs/plan.md in this repository for the full design and current status.`,
		Version: Version,

		// We print the error ourselves in main.go, so silence cobra's
		// default duplicate stderr output.
		SilenceErrors: true,
	}

	cmd.AddCommand(newGenerateCmd())
	cmd.AddCommand(newSyncGLSACmd())

	return cmd
}
