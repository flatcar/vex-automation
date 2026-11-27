package diff

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// linkPrefixes maps a vulnerability ID prefix to the page it links to.
// IDs with any other prefix are printed without a link.
var linkPrefixes = []struct{ prefix, url string }{
	{"CVE-", "https://www.cve.org/CVERecord?id="},
	{"GHSA-", "https://github.com/advisories/"},
	{"GO-", "https://pkg.go.dev/vuln/"},
	{"RUSTSEC-", "https://rustsec.org/advisories/"},
	{"GLSA-", "https://security.gentoo.org/glsa/"}, // linked without the "GLSA-"
}

// FormatChangelog writes the fixed entries of result as Markdown, like
// the "Security fixes" section of Flatcar's release notes: one line per
// package, sorted by name, e.g.
//
//   - curl ([CVE-2025-0665](https://www.cve.org/CVERecord?id=CVE-2025-0665))
//
// It returns "" when nothing was fixed.
func FormatChangelog(result Result) string {
	idsByName := namePackages(fixedIDsByPackage(result))
	names := slices.SortedFunc(maps.Keys(idsByName), func(a, b string) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a), strings.ToLower(b)), cmp.Compare(a, b))
	})

	var changelog strings.Builder
	for _, name := range names {
		var links []string
		for _, id := range slices.Sorted(maps.Keys(idsByName[name])) {
			links = append(links, link(id))
		}
		fmt.Fprintf(&changelog, "- %s (%s)\n", name, strings.Join(links, ", "))
	}
	return changelog.String()
}

// changelogPackage is one line of the changelog. Packages of different
// ecosystems may share a name, so both are part of the key.
type changelogPackage struct{ ecosystem, name string }

// fixedIDsByPackage collects the fixed IDs of each package.
//
// The Go standard library and toolchain are one line, "Go", in the
// release notes. So an ID is left out of it while the other of the two
// still has it open, and entirely while the new release ships an
// unchecked copy of the other one.
func fixedIDsByPackage(result Result) map[changelogPackage]map[string]bool {
	openGoIDs := map[string]bool{}
	for _, entry := range result.Entries {
		if isGo(entry) && isOpen(entry.Bucket) {
			openGoIDs[entry.ID] = true
		}
	}
	uncheckedGo := map[string]bool{}
	for _, skipped := range result.NotChecked.New {
		if skipped.Ecosystem == "golang" {
			uncheckedGo[skipped.Module] = true
		}
	}
	otherGoPackage := map[string]string{"stdlib": "toolchain", "toolchain": "stdlib"}

	ids := map[changelogPackage]map[string]bool{}
	for _, entry := range result.Entries {
		if entry.Bucket != BucketFixed {
			continue
		}
		pkg := changelogPackage{entry.Ecosystem, entry.Package}
		if isGo(entry) {
			if openGoIDs[entry.ID] || uncheckedGo[otherGoPackage[entry.Package]] {
				continue
			}
			pkg.name = "stdlib"
		}
		if ids[pkg] == nil {
			ids[pkg] = map[string]bool{}
		}
		ids[pkg][entry.ID] = true
	}
	return ids
}

// isOpen reports whether the new release may still have the vulnerability.
func isOpen(bucket Bucket) bool {
	return bucket == BucketStillAffected || bucket == BucketIntroduced || bucket == BucketReview
}

func isGo(entry Entry) bool {
	return entry.Ecosystem == "golang" && (entry.Package == "stdlib" || entry.Package == "toolchain")
}

// namePackages names packages as the release notes do (see shortName).
// A name shared by several packages is made unique: ebuilds get their
// category back, others get their ecosystem, e.g. "curl (cargo)".
func namePackages(ids map[changelogPackage]map[string]bool) map[string]map[string]bool {
	packagesPerName := map[string]int{}
	for pkg := range ids {
		packagesPerName[shortName(pkg)]++
	}
	idsByName := map[string]map[string]bool{}
	for pkg, pkgIDs := range ids {
		name := shortName(pkg)
		switch {
		case packagesPerName[name] == 1:
		case pkg.ecosystem == "ebuild":
			name = pkg.name
		default:
			name += " (" + pkg.ecosystem + ")"
		}
		idsByName[name] = pkgIDs
	}
	return idsByName
}

// shortName is an ebuild's name without its category, "Go" for the Go
// standard library, and the module path for other packages.
func shortName(pkg changelogPackage) string {
	if pkg.ecosystem == "golang" && pkg.name == "stdlib" {
		return "Go"
	}
	if _, name, found := strings.Cut(pkg.name, "/"); found && pkg.ecosystem == "ebuild" {
		return name
	}
	return pkg.name
}

func link(id string) string {
	for _, target := range linkPrefixes {
		if strings.HasPrefix(id, target.prefix) {
			return fmt.Sprintf("[%s](%s%s)", id, target.url, strings.TrimPrefix(id, "GLSA-"))
		}
	}
	return id
}
