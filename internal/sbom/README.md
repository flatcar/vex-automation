# sbom

Reads the SPDX SBOM that Flatcar publishes for each image (`Load`) and sorts its packages
by ecosystem, which decides which source can check them.

Each package's purl names its ecosystem. `pkg:ebuild/sys-apps/systemd@255.4-r2` is a
Gentoo ebuild, checked against GLSAs; it lands in `Document.Ebuilds` with its Portage
category. `pkg:golang/...` and `pkg:cargo/...` are Go modules and Rust crates compiled
into binaries, checked against OSV.dev; they land in `Document.Modules`. `FullName` gives
the name each source uses: `category/name` for ebuilds, the module path otherwise.

Everything else goes to `Document.Skipped` with a reason, so it can be reported as not
checked instead of looking clean. The Linux kernel is the main example; another Flatcar
pipeline handles its CVEs. A Go module whose version is `(devel)` can't be looked up
either, so it is skipped by name, which lets `diff` say "this module could not be
checked" rather than "this module is clean".

Go module purls are normalized the way OSV.dev expects: a `#v4` subpath becomes the
module path suffix `/v4`, and Syft's Go stdlib version `go1.25.3-X:nodwarf5` becomes
`1.25.3` (with the experiment suffix, OSV.dev would read it as a pre-release of 1.25.3,
still vulnerable to what 1.25.3 fixed).
