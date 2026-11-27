// Package portage implements a comparator for Portage (Gentoo ebuild)
// package versions and the GLSA range operators built on top of it.
//
// Version comparison is a direct port of Portage's own vercmp
// (lib/portage/versions.py), including its handling of leading zeros
// ("1.02" < "1.1"), implicit missing components ("1.0" < "1.0.0"), chained
// "_suffix" components ("1.0_rc1_p2") and revisions. Range operators follow
// lib/portage/glsa.py: "rge"/"rgt"/"rle"/"rlt" are revision-only
// comparisons within the same base version, and "eq" with a trailing "*"
// is Portage's "=*" glob match.
//
// If a version string can't be parsed at all, comparisons involving it
// return an error instead of silently guessing, so callers can decide how to
// handle it (e.g. report it as under investigation) rather than emit an
// incorrect VEX statement.
//
// GLSAs state which versions are vulnerable as ranges such as "lt 1.2.3",
// so every GLSA verdict in glsa.Match comes down to Satisfies. Plain
// semantic versioning can't be used instead: Gentoo versions have "-rN"
// revisions, "_p"/"_rc" suffixes and letters ("1.0a") that it orders
// differently or rejects.
package portage

import (
	"cmp"
	"fmt"
	"regexp"
	"strings"
)

// versionPattern mirrors Portage's ver_regexp: numeric dotted components,
// an optional single trailing letter, any number of "_suffix[number]"
// components, and an optional "-r<revision>".
var versionPattern = regexp.MustCompile(
	`^(\d+)((?:\.\d+)*)([a-z]?)((?:_(?:pre|p|beta|alpha|rc)\d*)*)(?:-r(\d+))?$`,
)

var suffixPattern = regexp.MustCompile(`^(alpha|beta|rc|pre|p)(\d*)$`)

// suffixValue orders "_suffix" kinds exactly as Portage's suffix_value does.
var suffixValue = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "p": 0}

type suffix struct {
	kind string
	// num is the suffix number as a digit string of arbitrary length, as
	// Portage compares it as an unbounded integer ("" counts as 0).
	num string
	// implicit marks the "_p-1" Portage uses when one side has fewer
	// suffixes; it sorts below every real "_p" number, including "_p0".
	implicit bool
}

// version is a parsed Portage version string.
type version struct {
	first    string   // first numeric component, digits only
	rest     []string // remaining numeric components, digits only
	letter   byte     // 0 if absent
	suffixes []suffix
	revision string // digits, "" if absent
	original string
}

// parseVersion parses a Portage version string such as "255.4-r2".
func parseVersion(s string) (version, error) {
	groups := versionPattern.FindStringSubmatch(s)
	if groups == nil {
		return version{}, fmt.Errorf("%q is not a recognizable Portage version", s)
	}
	// For "1.2.3b_rc1_p2-r4": first "1", rest ".2.3", letter "b",
	// suffixes "_rc1_p2", revision "4".
	first, rest, letter, suffixes, revision := groups[1], groups[2], groups[3], groups[4], groups[5]

	v := version{first: first, revision: revision, original: s}
	if rest != "" {
		v.rest = strings.Split(strings.TrimPrefix(rest, "."), ".")
	}
	if letter != "" {
		v.letter = letter[0]
	}
	if suffixes != "" {
		for _, part := range strings.Split(strings.TrimPrefix(suffixes, "_"), "_") {
			kindAndNumber := suffixPattern.FindStringSubmatch(part)
			if kindAndNumber == nil {
				return version{}, fmt.Errorf("%q: invalid suffix %q", s, part)
			}
			v.suffixes = append(v.suffixes, suffix{kind: kindAndNumber[1], num: kindAndNumber[2]})
		}
	}
	return v, nil
}

// base returns v's original text without its "-rN" revision.
func (v version) base() string {
	if i := strings.LastIndex(v.original, "-r"); i >= 0 {
		return v.original[:i]
	}
	return v.original
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

// compare is a port of Portage's vercmp. It compares the parts of the two
// versions from left to right; the first part that differs decides.
func (v version) compare(other version) int {
	steps := []func() int{
		func() int { return compareDigits(v.first, other.first) },
		func() int { return compareComponents(v.rest, other.rest) },
		// A letter sorts above no letter (letter 0), so "1.0a" > "1.0".
		func() int { return cmp.Compare(v.letter, other.letter) },
		func() int { return compareSuffixes(v.suffixes, other.suffixes) },
		func() int { return compareDigits(v.revision, other.revision) },
	}
	for _, step := range steps {
		if order := step(); order != 0 {
			return order
		}
	}
	return 0
}

// compareComponents compares the dotted components after the first one.
// A missing component sorts below any present one, so "1.0" < "1.0.0".
func compareComponents(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if order := compareComponent(a[i], b[i]); order != 0 {
			return order
		}
	}
	return cmp.Compare(len(a), len(b))
}

// compareComponent compares two components as integers, unless one has a
// leading zero: then both are compared as decimal fractions, so "02" < "1".
func compareComponent(a, b string) int {
	if a[0] != '0' && b[0] != '0' {
		return compareDigits(a, b)
	}
	width := max(len(a), len(b))
	return strings.Compare(padRight(a, width), padRight(b, width))
}

// compareSuffixes compares "_suffix" lists such as "_rc1_p2": first by
// kind (alpha < beta < pre < rc < p), then by number.
func compareSuffixes(a, b []suffix) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		sa, sb := suffixAt(a, i), suffixAt(b, i)
		if sa.kind != sb.kind {
			return cmp.Compare(suffixValue[sa.kind], suffixValue[sb.kind])
		}
		// The implicit "_p-1" sorts below every real "_p" number.
		if sa.implicit && !sb.implicit {
			return -1
		}
		if sb.implicit && !sa.implicit {
			return 1
		}
		if order := compareDigits(sa.num, sb.num); order != 0 {
			return order
		}
	}
	return 0
}

// suffixAt returns s[i], or the implicit "_p-1" Portage uses for a missing
// suffix (so "1.0" < "1.0_p0" but "1.0_rc1" < "1.0").
func suffixAt(s []suffix, i int) suffix {
	if i < len(s) {
		return s[i]
	}
	return suffix{kind: "p", implicit: true}
}

// compareDigits compares two non-negative decimal integers given as digit
// strings of arbitrary length ("" counts as 0).
func compareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	return cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
}

func padRight(s string, width int) string {
	return s + strings.Repeat("0", width-len(s))
}

// Satisfies reports whether installed satisfies "installed <op> constraint",
// e.g. Satisfies("2.0.7", "ge", "2.0.6") reports whether 2.0.7 >= 2.0.6.
// Supported ops are the GLSA <unaffected>/<vulnerable> range attributes:
//
//   - "ge", "gt", "le", "lt", "eq": plain version comparisons. "eq" with a
//     trailing "*" (e.g. "2.4*") is Portage's "=*" glob, which matches on
//     version component boundaries only ("2.4.1" matches, "2.40" doesn't).
//   - "rge", "rgt", "rle", "rlt": revision-only comparisons. They only match
//     an installed version whose base version is spelled exactly like
//     constraint's (Portage's "~" match), and
//     then compare the "-rN" revisions alone, as in Portage's glsa.py
//     revisionMatch. So "1.0-r2" satisfies "rge 1.0-r1", but "1.5" doesn't.
func Satisfies(installed, op, constraint string) (bool, error) {
	if op == "eq" && strings.HasSuffix(constraint, "*") {
		return globMatch(installed, strings.TrimSuffix(constraint, "*"))
	}

	vi, err := parseVersion(installed)
	if err != nil {
		return false, err
	}
	vc, err := parseVersion(constraint)
	if err != nil {
		return false, err
	}

	plainOp, revisionOnly := strings.CutPrefix(op, "r")
	accepts, known := rangeOps[plainOp]
	if !known || (revisionOnly && plainOp == "eq") {
		return false, fmt.Errorf("unsupported range operator %q", op)
	}
	if !revisionOnly {
		return accepts(vi.compare(vc)), nil
	}
	// Portage matches the base with a "~" atom, which requires the version
	// text to be identical, so "1.010" is not "1.01".
	if vi.base() != vc.base() {
		return false, nil
	}
	return accepts(compareDigits(vi.revision, vc.revision)), nil
}

// rangeOps maps each plain GLSA range operator to the comparison results
// (-1, 0 or 1 for installed vs. constraint) it accepts.
var rangeOps = map[string]func(order int) bool{
	"lt": func(order int) bool { return order < 0 },
	"le": func(order int) bool { return order <= 0 },
	"eq": func(order int) bool { return order == 0 },
	"ge": func(order int) bool { return order >= 0 },
	"gt": func(order int) bool { return order > 0 },
}

// globMatch implements Portage's "=*" match (lib/portage/dep, match_from_list):
// a literal prefix match after normalizing leading zeros of the first
// component, which must end on a version component boundary (Gentoo bug
// 560466: "1*" must not match "10").
func globMatch(installed, prefix string) (bool, error) {
	if prefix == "" {
		return false, fmt.Errorf("empty version glob")
	}
	// The glob without its "*" must itself be a valid version prefix.
	if _, err := parseVersion(prefix); err != nil {
		return false, err
	}
	if _, err := parseVersion(installed); err != nil {
		return false, err
	}

	installed, prefix = trimLeadingZeros(installed), trimLeadingZeros(prefix)
	if !strings.HasPrefix(installed, prefix) {
		return false, nil
	}
	if len(installed) == len(prefix) {
		return true, nil
	}
	next := installed[len(prefix)]
	if strings.IndexByte("._-", next) >= 0 {
		return true, nil
	}
	return isDigit(prefix[len(prefix)-1]) != isDigit(next), nil
}

func trimLeadingZeros(v string) string {
	t := strings.TrimLeft(v, "0")
	if t == "" || !isDigit(t[0]) {
		return "0" + t
	}
	return t
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
