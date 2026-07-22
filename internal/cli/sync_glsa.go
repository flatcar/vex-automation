package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/flatcar/vex-automation/internal/glsasync"
)

// newSyncGLSACmd builds the "sync-glsa" subcommand: a convenience wrapper
// so a user doesn't have to manually locate or maintain their own copy of
// the upstream GLSA corpus before running "generate --glsa-dir".
func newSyncGLSACmd() *cobra.Command {
	var (
		dest    string
		repo    string
		timeout time.Duration
	)

	cmd := &cobra.Command{
		Use:   "sync-glsa",
		Short: "Download or update a local mirror of the upstream Gentoo GLSA corpus",
		Long: `sync-glsa clones (on first run) or fast-forwards (on later runs) a local
directory containing every upstream Gentoo GLSA *.xml advisory, so you don't
have to source or keep one up to date by hand before running "generate
--glsa-dir".

It shells out to "git" against the same corpus Gentoo publishes at
` + glsasync.DefaultRepoURL + `, rather than
re-fetching or re-parsing individual files itself.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			res, err := glsasync.Sync(ctx, dest, repo)
			if err != nil {
				return err
			}
			action := "Updated"
			if res.Cloned {
				action = "Cloned"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s GLSA mirror at %s (%d advisories)\n", action, res.Dest, res.FileCount)
			return nil
		},
	}

	cmd.Flags().StringVar(&dest, "dest", "glsa-data", "local directory to sync the GLSA corpus into")
	cmd.Flags().StringVar(&repo, "repo", glsasync.DefaultRepoURL, "upstream GLSA git repository to sync from")
	cmd.Flags().DurationVar(&timeout, "timeout", glsasync.DefaultTimeout, "maximum time to allow the clone/update to run")

	return cmd
}
