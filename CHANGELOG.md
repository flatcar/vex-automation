# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- `sync-glsa` subcommand: clones or fast-forward-updates a local mirror of
  the upstream Gentoo GLSA corpus (`anongit.gentoo.org/git/data/glsa.git`)
  via `git`, so `generate --glsa-dir` has a ready-made input directory
  without the user sourcing one by hand.
- `generate` subcommand: reads a Flatcar SPDX SBOM and a local Gentoo GLSA XML
  directory, matches every ebuild package against every advisory (Portage
  version-range semantics, arch-filtered), and emits an OpenVEX document via
  `github.com/openvex/go-vex`. See `docs/plan.md` §3–§6 for the full PoC design.
- Initial Go CLI scaffold (`flatcar-vex`), built on Cobra.
