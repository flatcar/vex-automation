package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/flatcar/vex-automation/internal/glsasync"
)

func newSyncGLSACmd() *cobra.Command {
	var (
		dest    string
		repo    string
		timeout time.Duration
	)

	cmd := &cobra.Command{
		Use:   "sync-glsa",
		Short: "Download or update a local mirror of the upstream Gentoo GLSA corpus",
		Long: `sync-glsa clones (on first run) or updates (on later runs) a local
directory containing every upstream Gentoo GLSA *.xml advisory, so you don't
have to source or keep one up to date by hand before running "generate
--glsa-dir".

It shells out to "git" against the same corpus Gentoo publishes at
` + glsasync.DefaultRepoURL + `, rather than
re-fetching or re-parsing individual files itself.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(cmd.Context(), timeout)
			defer cancel()
			result, err := glsasync.Sync(ctx, dest, repo, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), describeSync(result))
			return err
		},
	}

	cmd.Flags().StringVar(&dest, "dest", "glsa-data", "local directory to sync the GLSA corpus into")
	cmd.Flags().StringVar(&repo, "repo", glsasync.DefaultRepoURL, "upstream GLSA git repository to sync from")
	cmd.Flags().DurationVar(&timeout, "timeout", glsasync.DefaultTimeout, "maximum time to allow the clone/update to run")

	return cmd
}

// describeSync summarizes what Sync did in one line.
func describeSync(result glsasync.Result) string {
	switch {
	case result.Cloned:
		return fmt.Sprintf("Cloned GLSA mirror at %s (%d advisories, %s)", result.Dest, result.FileCount, short(result.NewCommit))
	case result.OldCommit == "":
		return fmt.Sprintf("Updated GLSA mirror at %s (%d advisories, now at %s)", result.Dest, result.FileCount, short(result.NewCommit))
	case result.OldCommit == result.NewCommit:
		return fmt.Sprintf("GLSA mirror at %s is already up to date (%d advisories)", result.Dest, result.FileCount)
	default:
		return fmt.Sprintf("Updated GLSA mirror at %s (%d advisories, %s -> %s)", result.Dest, result.FileCount, short(result.OldCommit), short(result.NewCommit))
	}
}

// short abbreviates a commit hash for display.
func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
