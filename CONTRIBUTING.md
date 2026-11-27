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
3. The same workflow run squash-merges the Release PR right away, as the `flatcar-infra`
   bot user with its token (`BOT_PR_TOKEN` repository secret). `flatcar-infra` bypasses the
   branch protection ruleset (configured in `flatcar/safe-settings-admin`), the same setup
   `flatcar/scripts` uses. The default `GITHUB_TOKEN` can't do this: the GitHub Actions app
   can't be given a working ruleset bypass, and its merges don't trigger workflows, so the
   release step below would never run. If `BOT_PR_TOKEN` is missing the workflow only warns,
   and a maintainer merges the Release PR by hand.
4. Once merged, release-please tags the release as plain `vX.Y.Z` and publishes a GitHub
   Release with generated notes, and, in the same workflow run, builds and attaches release
   archives and `.deb`/`.rpm`/Arch packages via `goreleaser` (see `.goreleaser.yaml`). Tags carry no `flatcar-vex-`
   component prefix (`include-component-in-tag: false` in `release-please-config.json`)
   because goreleaser only accepts semver tags. release-please keeps using `GITHUB_TOKEN`, so
   its tag doesn't trigger `release.yml`; goreleaser runs in the *same* workflow run instead.
5. [`.github/workflows/release.yml`](./.github/workflows/release.yml) (tag-push triggered)
   remains as a manual fallback, e.g. for re-running a release build off a manually pushed
   `vX.Y.Z` tag.

Every PR merged to `main` with a releasable `feat:`/`fix:`/etc. title is therefore released
on its own, straight away. Changes with non-releasing types (`docs:`, `chore:`, `ci:`, ...)
wait for the next releasable one.