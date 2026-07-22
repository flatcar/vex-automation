// Package portage implements a best-effort comparator for Portage (Gentoo
// ebuild) package versions, following the version syntax described in the
// Package Manager Specification (PMS) closely enough to correctly evaluate
// the vast majority of real-world GLSA version ranges.
//
// # Known limitations
//
// This is intentionally not a complete PMS implementation:
//   - Numeric components are compared as integers. PMS technically compares
//     components with leading zeros as decimal strings (so "1.010" < "1.02"
//     because "010" < "02" as strings once trailing zeros are considered) —
//     an edge case essentially never seen in practice for the packages
//     Flatcar ships. This implementation instead compares them numerically
//     (so "1.010" == "1.10", since both parse to the integer 10), which is
//     correct for the overwhelming majority of real version strings.
//   - Only one "_suffix" component (e.g. "_alpha1", "_p20240101") is
//     supported per version, which matches real-world usage; the PMS
//     grammar technically allows a chain of several.
//
// If a version string can't be parsed at all, comparisons involving it
// return an error instead of silently guessing, so callers can decide how to
// handle (e.g. treat as "unknown"/needs investigation) rather than emit an
// incorrect VEX statement.
package portage

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// versionPattern captures: numeric dotted components, an optional single
// trailing letter, an optional "_suffix[number]" component, and an optional
// "-r<revision>".
//
// Examples this matches: "1.2.3", "2.0.6", "3.18.1", "1.2c", "1.0_pre3",
// "1.2.3-r1", "1.2.3_p20240101-r2".
var versionPattern = regexp.MustCompile(
	`^(?P<numeric>\d+(?:\.\d+)*)` +
		`(?P<letter>[a-z])?` +
		`(?:_(?P<suffixkind>alpha|beta|pre|rc|p)(?P<suffixnum>\d*))?` +
		`(?:-r(?P<revision>\d+))?$`,
)

// suffixRank orders the "_suffix" component per PMS: alpha < beta < pre < rc
// < (no suffix) < p.
var suffixRank = map[string]int{
	"alpha": 0,
	"beta":  1,
	"pre":   2,
	"rc":    3,
	"":      4,
	"p":     5,
}

// version is a parsed Portage version string.
type version struct {
	numeric    []int
	letter     byte // 0 if absent
	suffixKind string
	suffixNum  int
	revision   int
	original   string
}

// parseVersion parses a Portage version string such as "255.4-r2".
func parseVersion(s string) (version, error) {
	m := versionPattern.FindStringSubmatch(s)
	if m == nil {
		return version{}, fmt.Errorf("%q is not a recognizable Portage version", s)
	}

	groups := map[string]string{}
	for i, name := range versionPattern.SubexpNames() {
		if name != "" {
			groups[name] = m[i]
		}
	}

	var v version
	v.original = s

	for _, part := range strings.Split(groups["numeric"], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return version{}, fmt.Errorf("%q: invalid numeric component %q: %w", s, part, err)
		}
		v.numeric = append(v.numeric, n)
	}

	if groups["letter"] != "" {
		v.letter = groups["letter"][0]
	}

	v.suffixKind = groups["suffixkind"]
	if groups["suffixnum"] != "" {
		n, err := strconv.Atoi(groups["suffixnum"])
		if err != nil {
			return version{}, fmt.Errorf("%q: invalid suffix number %q: %w", s, groups["suffixnum"], err)
		}
		v.suffixNum = n
	}

	if groups["revision"] != "" {
		n, err := strconv.Atoi(groups["revision"])
		if err != nil {
			return version{}, fmt.Errorf("%q: invalid revision %q: %w", s, groups["revision"], err)
		}
		v.revision = n
	}

	return v, nil
}

// Compare compares two Portage version strings. It returns -1, 0 or 1 if a
// is respectively less than, equal to, or greater than b. An error is
// returned if either version string cannot be parsed.
func Compare(a, b string) (int, error) {
	va, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	return va.compare(vb), nil
}

func (v version) compare(o version) int {
	if c := compareNumeric(v.numeric, o.numeric); c != 0 {
		return c
	}
	if c := compareByte(v.letter, o.letter); c != 0 {
		return c
	}
	if c := suffixRank[v.suffixKind] - suffixRank[o.suffixKind]; c != 0 {
		return sign(c)
	}
	if c := v.suffixNum - o.suffixNum; c != 0 {
		return sign(c)
	}
	return sign(v.revision - o.revision)
}

func compareNumeric(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			return sign(av - bv)
		}
	}
	return 0
}

func compareByte(a, b byte) int {
	return sign(int(a) - int(b))
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// Satisfies reports whether version satisfies the constraint "installed <op>
// constraint", e.g. Satisfies("2.0.7", "ge", "2.0.6") reports whether
// 2.0.7 >= 2.0.6. Supported ops are "ge", "gt", "le", "lt", "eq", matching
// the operators used in GLSA <unaffected>/<vulnerable> range attributes.
// "rge"/"rlt" (revision-only ranges) are treated the same as "ge"/"lt" here,
// since Flatcar's SBOM always reports the full version including revision.
func Satisfies(installed, op, constraint string) (bool, error) {
	// GLSA "eq" ranges may use a trailing "*" wildcard, e.g. "2.4*", meaning
	// "any version with this prefix" (handled as a plain string prefix match
	// rather than full version parsing, per Gentoo's glsa-check semantics).
	if op == "eq" && strings.HasSuffix(constraint, "*") {
		return strings.HasPrefix(installed, strings.TrimSuffix(constraint, "*")), nil
	}

	c, err := Compare(installed, constraint)
	if err != nil {
		return false, err
	}

	switch op {
	case "ge", "rge":
		return c >= 0, nil
	case "gt":
		return c > 0, nil
	case "le":
		return c <= 0, nil
	case "lt", "rlt":
		return c < 0, nil
	case "eq":
		return c == 0, nil
	default:
		return false, fmt.Errorf("unsupported range operator %q", op)
	}
}
