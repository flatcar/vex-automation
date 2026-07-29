# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0 (2026-07-29)


### Features

* Add basic SBOM parsing from GLSA ([9abf485](https://github.com/flatcar/vex-automation/commit/9abf485abf311f2759cce4f08796612ab46d04d1))
* Add basic SBOM parsing from GLSA ([f599aa9](https://github.com/flatcar/vex-automation/commit/f599aa9005e8f4f3971778ce2143bca4e0b213da))
* Add go release setup ([#9](https://github.com/flatcar/vex-automation/issues/9)) ([e48cfd2](https://github.com/flatcar/vex-automation/commit/e48cfd2fdfe9c51b0788065299ed441859e6b8f0))
* Bootstrap the go project ([a047d47](https://github.com/flatcar/vex-automation/commit/a047d47ae97532aca44adc59614fb825306f6e53))
* Initialize the go cli project ([a3f2708](https://github.com/flatcar/vex-automation/commit/a3f270893371d00333f0161386d922eb7e493040))

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
