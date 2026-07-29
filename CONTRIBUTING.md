Welcome! We're so glad you're here and interested in contributing to Flatcar! 💖

Whether you're fixing a bug, adding a feature, or improving docs — we appreciate you!

For more detailed guidelines (finding issues, community meetings, PR lifecycle, commit message format, and more), check out the [main Flatcar CONTRIBUTING guide](https://github.com/flatcar/Flatcar/blob/main/CONTRIBUTING.md).

If you want to file an issue for any Flatcar repository, please use the [central Flatcar issue tracker](https://github.com/flatcar/Flatcar/issues).

---

## Repository Specific Guidelines

Any guidelines specific to this repository that are not covered in the main contribution guide will be listed here.

<!-- Add repo-specific guidelines below this line -->

This project is written in Go. See [`docs/plan.md`](./docs/plan.md) for the architecture,
tech stack, and phased roadmap before proposing changes. Run `make check` before opening a
pull request — it runs the same format/lint/vet/test checks as CI. Run `make help` to see
all available targets.

### PR titles must follow Conventional Commits

This repository uses [release-please](https://github.com/googleapis/release-please) to
automate versioning, `CHANGELOG.md` generation, and releases from commit history on `main`.
For that to work, your **PR title** must follow the
[Conventional Commits](https://www.conventionalcommits.org/) format, e.g.:

```
feat: add OSV.dev source matching
fix(cli): reject negative --osv-timeout values
docs: document the release automation
```

The PR title is checked automatically by `.github/workflows/pr-title-lint.yml` and is what
release-please parses to decide the next version bump (`feat` → minor, `fix` → patch,
`!`/`BREAKING CHANGE` → major) and to write the changelog entry. Individual commits within
your branch can be messy (`wip`, `address review`, etc.) — only the PR title matters.

### Merge strategy exception: squash merge only

Unlike most Flatcar repositories, which merge PRs as merge commits (the org default,
configured in [`safe-settings-admin`](https://github.com/flatcar/safe-settings-admin)),
**this repository is configured for squash-merge only** (see
[`.github/repos/vex-automation.yml`](https://github.com/flatcar/safe-settings-admin/blob/main/.github/repos/vex-automation.yml)
in that repo). This is required so each PR lands on `main` as exactly one commit whose
message is the PR title, which is what release-please parses per release. If this repo's
merge settings ever look "wrong" compared to other Flatcar repos, this is why.

### How the release automation works

1. Merging a PR to `main` with a Conventional Commits-formatted title triggers
   [`.github/workflows/release-please.yml`](./.github/workflows/release-please.yml).
2. release-please maintains a standing "Release PR" that accumulates the changelog and
   next version number as qualifying PRs merge.
3. **This Release PR merges itself automatically — no human review or manual merge click
   is required.** The workflow enables GitHub's native auto-merge on it as soon as it's
   opened/updated. Auto-merge still waits for this repo's normal required status checks
   (lint, tests, CodeQL, etc.) to pass on the Release PR's branch before merging; it only
   skips the required-approving-review rule, since this PR is never meant to be
   human-reviewed (there's nothing to review — its content is entirely generated from
   already-reviewed, already-merged commits). This mirrors how `security-triage` runs
   `semantic-release` fully automatically via a bypassed bot identity.
4. Once merged, release-please tags the release and publishes a GitHub Release with
   generated notes, and, in the same workflow run, builds and attaches release binaries via
   `goreleaser` (see `.goreleaser.yaml`). No extra secrets or personal access tokens are
   required anywhere in this pipeline — the goreleaser build runs as a later step in the
   *same* workflow run that release-please just ran in, rather than depending on the new
   tag re-triggering a separate workflow (which the default `GITHUB_TOKEN` cannot do).
5. [`.github/workflows/release.yml`](./.github/workflows/release.yml) (tag-push triggered)
   remains as a manual fallback, e.g. for re-running a release build off a manually pushed
   tag.

This means merging any PR with a `feat:`/`fix:`/etc. title to `main` can result in a new
tagged release within minutes, with no further action from anyone. If you need to hold off
a release (e.g. to batch several changes), merge PRs with a non-releasing title prefix
(`chore:`, `docs:`, `test:`, etc.) or ask a maintainer to pause the Release PR's auto-merge
before merging your PR.