package diff

import (
	"testing"

	"github.com/flatcar/vex-automation/internal/sbom"
)

func TestFormatChangelog(t *testing.T) {
	fixed := func(id, pkg string, eco sbom.Ecosystem) Entry {
		return Entry{ID: id, Bucket: BucketFixed, Package: pkg, Ecosystem: eco}
	}
	res := Result{Entries: []Entry{
		fixed("CVE-2025-2", "net-misc/curl", "ebuild"),
		fixed("CVE-2025-1", "net-misc/curl", "ebuild"),
		fixed("CVE-2025-1", "net-misc/curl", "ebuild"),
		fixed("CVE-2026-9", "stdlib", "golang"),
		fixed("GO-2026-1", "toolchain", "golang"),
		fixed("GHSA-aaaa-bbbb-cccc", "github.com/x/y", "golang"),
		fixed("RUSTSEC-2026-0001", "some-crate", "cargo"),
		fixed("GLSA-202601-01", "dev-libs/foo", "ebuild"),
		fixed("CVE-2026-3", "sys-apps/foo", "ebuild"),
		fixed("OSV-2026-7", "app-misc/bar", "ebuild"),
		{ID: "CVE-2026-5", Bucket: BucketIntroduced, Package: "app-misc/new", Ecosystem: "ebuild"},
		{ID: "CVE-2026-6", Bucket: BucketRemoved, Package: "app-misc/gone", Ecosystem: "ebuild"},
		{ID: "CVE-2026-7", Bucket: BucketReview, Package: "app-misc/unsure", Ecosystem: "ebuild"},
	}}

	want := "- bar (OSV-2026-7)\n" +
		"- curl ([CVE-2025-1](https://www.cve.org/CVERecord?id=CVE-2025-1), [CVE-2025-2](https://www.cve.org/CVERecord?id=CVE-2025-2))\n" +
		"- dev-libs/foo ([GLSA-202601-01](https://security.gentoo.org/glsa/202601-01))\n" +
		"- github.com/x/y ([GHSA-aaaa-bbbb-cccc](https://github.com/advisories/GHSA-aaaa-bbbb-cccc))\n" +
		"- Go ([CVE-2026-9](https://www.cve.org/CVERecord?id=CVE-2026-9), [GO-2026-1](https://pkg.go.dev/vuln/GO-2026-1))\n" +
		"- some-crate ([RUSTSEC-2026-0001](https://rustsec.org/advisories/RUSTSEC-2026-0001))\n" +
		"- sys-apps/foo ([CVE-2026-3](https://www.cve.org/CVERecord?id=CVE-2026-3))\n"

	if got := FormatChangelog(res); got != want {
		t.Fatalf("FormatChangelog =\n%s\nwant\n%s", got, want)
	}
}

func TestFormatChangelogEmpty(t *testing.T) {
	res := Result{Entries: []Entry{{ID: "CVE-1", Bucket: BucketStillAffected, Package: "a/b", Ecosystem: "ebuild"}}}
	if got := FormatChangelog(res); got != "" {
		t.Fatalf("FormatChangelog = %q, want empty", got)
	}
}

func TestFormatChangelogSeparatesEcosystemsSharingAName(t *testing.T) {
	fixed := func(id, pkg string, eco sbom.Ecosystem) Entry {
		return Entry{ID: id, Bucket: BucketFixed, Package: pkg, Ecosystem: eco}
	}
	res := Result{Entries: []Entry{
		fixed("CVE-2026-1", "net-misc/curl", "ebuild"),
		fixed("RUSTSEC-2026-0001", "curl", "cargo"),
		fixed("CVE-2026-2", "stdlib", "golang"),
		fixed("CVE-2026-3", "toolchain", "golang"),
	}}

	want := "- curl (cargo) ([RUSTSEC-2026-0001](https://rustsec.org/advisories/RUSTSEC-2026-0001))\n" +
		"- Go ([CVE-2026-2](https://www.cve.org/CVERecord?id=CVE-2026-2), [CVE-2026-3](https://www.cve.org/CVERecord?id=CVE-2026-3))\n" +
		"- net-misc/curl ([CVE-2026-1](https://www.cve.org/CVERecord?id=CVE-2026-1))\n"

	if got := FormatChangelog(res); got != want {
		t.Fatalf("FormatChangelog =\n%s\nwant\n%s", got, want)
	}
}

func TestFormatChangelogSkipsGoIDsStillOpenInTheOtherPackage(t *testing.T) {
	entry := func(id, pkg string, b Bucket) Entry {
		return Entry{ID: id, Bucket: b, Package: pkg, Ecosystem: "golang"}
	}
	res := Result{Entries: []Entry{
		entry("CVE-2026-1", "toolchain", BucketFixed),
		entry("CVE-2026-1", "stdlib", BucketStillAffected),
		entry("CVE-2026-2", "stdlib", BucketFixed),
		entry("CVE-2026-2", "toolchain", BucketReview),
		entry("CVE-2026-3", "toolchain", BucketFixed),
		entry("CVE-2026-3", "stdlib", BucketIntroduced),
		entry("CVE-2026-4", "stdlib", BucketFixed),
		entry("CVE-2026-4", "toolchain", BucketRemoved),
	}}

	want := "- Go ([CVE-2026-4](https://www.cve.org/CVERecord?id=CVE-2026-4))\n"
	if got := FormatChangelog(res); got != want {
		t.Fatalf("FormatChangelog =\n%s\nwant\n%s", got, want)
	}
}

func TestFormatChangelogSkipsGoFixesWithAnUncheckedSibling(t *testing.T) {
	toolOld, toolNew := gomod("toolchain", "1.25.0"), gomod("toolchain", "1.25.1")
	newSide := side([]sbom.Package{toolNew})
	newSide.Doc.Skipped = []sbom.SkippedPackage{{Name: "stdlib", Version: "(devel)", PURL: "pkg:golang/stdlib@(devel)",
		Reason: "version is not queryable", Ecosystem: "golang", Module: "stdlib"}}

	res := Compute(Input{
		Old: side([]sbom.Package{toolOld}, osvFinding("CVE-2026-1", toolOld, "GO-1")),
		New: newSide,
	})
	if got := FormatChangelog(res); got != "" {
		t.Fatalf("FormatChangelog = %q, want empty", got)
	}
}
