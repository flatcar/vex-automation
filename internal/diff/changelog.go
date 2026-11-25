package diff

import (
	"fmt"
	"sort"
	"strings"
)

// linkPrefixes maps a vulnerability ID prefix to the URL its ID is linked
// to in the changelog. IDs with no known prefix are printed unlinked.
var linkPrefixes = []struct {
	prefix string
	url    func(id string) string
}{
	{"CVE-", func(id string) string { return "https://www.cve.org/CVERecord?id=" + id }},
	{"GHSA-", func(id string) string { return "https://github.com/advisories/" + id }},
	{"GO-", func(id string) string { return "https://pkg.go.dev/vuln/" + id }},
	{"RUSTSEC-", func(id string) string { return "https://rustsec.org/advisories/" + id }},
	{"GLSA-", func(id string) string { return "https://security.gentoo.org/glsa/" + strings.TrimPrefix(id, "GLSA-") }},
}

// FormatChangelog renders the fixed bucket of res as Markdown in the style
// of Flatcar's "Security fixes" release notes: one line per package,
// sorted by name, e.g.
//
//   - curl ([CVE-2025-0665](https://www.cve.org/CVERecord?id=CVE-2025-0665))
//
// It returns "" when nothing was fixed. Go standard library and toolchain
// IDs are left out while either package is still affected by them or the
// new release ships an unchecked copy of the other one.
func FormatChangelog(res Result) string {
	// Group by ecosystem and package, merging the Go standard library and
	// toolchain, so distinct packages sharing a name stay apart. The merged
	// "Go" line must not announce an ID that the other of the two packages
	// still has open (affected now, or unknown), nor any ID while the new
	// release ships an unchecked copy of the other package.
	type group struct{ eco, pkg string }
	isGo := func(e Entry) bool {
		return e.Ecosystem == "golang" && (e.Package == "stdlib" || e.Package == "toolchain")
	}
	openGoIDs := map[string]bool{}
	for _, e := range res.Entries {
		if isGo(e) && (e.Bucket == BucketStillAffected || e.Bucket == BucketIntroduced || e.Bucket == BucketReview) {
			openGoIDs[e.ID] = true
		}
	}
	uncheckedGo := map[string]bool{}
	for _, s := range res.NotChecked.New {
		if s.Ecosystem == "golang" {
			uncheckedGo[s.Module] = true
		}
	}
	goSibling := map[string]string{"stdlib": "toolchain", "toolchain": "stdlib"}
	idsByGroup := map[group]map[string]bool{}
	for _, e := range res.Entries {
		if e.Bucket != BucketFixed {
			continue
		}
		g := group{e.Ecosystem, e.Package}
		if isGo(e) {
			if openGoIDs[e.ID] || uncheckedGo[goSibling[e.Package]] {
				continue
			}
			g.pkg = "stdlib"
		}
		if idsByGroup[g] == nil {
			idsByGroup[g] = map[string]bool{}
		}
		idsByGroup[g][e.ID] = true
	}

	// Name packages as the release notes do: ebuilds without their
	// category, the Go standard library as "Go", modules by their path.
	// A name shared by several groups is qualified: ebuilds by category,
	// others by ecosystem (e.g. "curl (cargo)" next to "net-misc/curl").
	shortName := func(g group) string {
		switch {
		case g.eco == "ebuild":
			_, name, found := strings.Cut(g.pkg, "/")
			if found {
				return name
			}
		case g.eco == "golang" && g.pkg == "stdlib":
			return "Go"
		}
		return g.pkg
	}
	groupsByName := map[string]int{}
	for g := range idsByGroup {
		groupsByName[shortName(g)]++
	}
	idsByName := map[string]map[string]bool{}
	for g, ids := range idsByGroup {
		name := shortName(g)
		if groupsByName[name] > 1 {
			if g.eco == "ebuild" {
				name = g.pkg
			} else {
				name += " (" + g.eco + ")"
			}
		}
		idsByName[name] = ids
	}

	names := make([]string, 0, len(idsByName))
	for n := range idsByName {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := strings.ToLower(names[i]), strings.ToLower(names[j])
		if a != b {
			return a < b
		}
		return names[i] < names[j]
	})

	var sb strings.Builder
	for _, n := range names {
		ids := make([]string, 0, len(idsByName[n]))
		for id := range idsByName[n] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		links := make([]string, len(ids))
		for i, id := range ids {
			links[i] = link(id)
		}
		fmt.Fprintf(&sb, "- %s (%s)\n", n, strings.Join(links, ", "))
	}
	return sb.String()
}

func link(id string) string {
	for _, lp := range linkPrefixes {
		if strings.HasPrefix(id, lp.prefix) {
			return fmt.Sprintf("[%s](%s)", id, lp.url(id))
		}
	}
	return id
}
