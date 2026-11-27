package cli

import (
	"fmt"
	"time"

	"github.com/flatcar/vex-automation/internal/source/glsa"
	"github.com/spf13/cobra"
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
--glsa-dir". An update makes the directory match upstream exactly, so any
other files in it are removed.

It uses a built-in git implementation, so git does not need to be
installed, and reads the same corpus Gentoo publishes at
` + glsa.DefaultRepoURL + `.
You can also clone that repository yourself
(git clone --depth 1 <url> glsa-data) and pass it to --glsa-dir.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(cmd.Context(), timeout)
			defer cancel()
			result, err := glsa.Sync(ctx, dest, repo, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), describeSync(result))
			return err
		},
	}

	cmd.Flags().StringVar(&dest, "dest", "glsa-data", "local directory to sync the GLSA corpus into")
	cmd.Flags().StringVar(&repo, "repo", glsa.DefaultRepoURL, "upstream GLSA git repository to sync from")
	cmd.Flags().DurationVar(&timeout, "timeout", glsa.DefaultTimeout, "maximum time to allow the clone/update to run")

	return cmd
}

// describeSync summarizes what Sync did in one line.
func describeSync(result glsa.SyncResult) string {
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
