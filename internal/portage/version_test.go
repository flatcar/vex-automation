package portage

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// readOracle returns the tab-separated records of a testdata file generated
// from Portage itself (see the header of each file).
func readOracle(t *testing.T, name string, fields int) [][]string {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatalf("opening oracle: %v", err)
	}
	defer func() { _ = f.Close() }()
	var records [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "#") {
			continue
		}
		rec := strings.Split(sc.Text(), "\t")
		if len(rec) != fields {
			t.Fatalf("malformed oracle line %q", sc.Text())
		}
		records = append(records, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading oracle: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("empty oracle")
	}
	return records
}

// TestCompareMatchesPortage checks Compare against vercmp results (and
// version validity) produced by Portage's own versions.py.
func TestCompareMatchesPortage(t *testing.T) {
	for _, rec := range readOracle(t, "portage_vercmp.tsv", 3) {
		got, err := Compare(rec[0], rec[1])
		if rec[2] == "ERR" {
			if err == nil {
				t.Errorf("Compare(%q, %q) = %d, want an error (Portage rejects the version)", rec[0], rec[1], got)
			}
			continue
		}
		want, _ := strconv.Atoi(rec[2])
		if err != nil || got != want {
			t.Errorf("Compare(%q, %q) = %d, %v; Portage says %d", rec[0], rec[1], got, err, want)
		}
	}
}

// TestGlobMatchesPortage checks the "=*" range against Portage's
// match_from_list.
func TestGlobMatchesPortage(t *testing.T) {
	for _, rec := range readOracle(t, "portage_glob.tsv", 3) {
		got, err := Satisfies(rec[0], "eq", rec[1]+"*")
		if want := rec[2] == "1"; err != nil || got != want {
			t.Errorf("Satisfies(%q, eq, %q*) = %v, %v; Portage says %v", rec[0], rec[1], got, err, want)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.0.6", "2.0.6", 0},
		{"2.0.5", "2.0.6", -1},
		{"2.0.7", "2.0.6", 1},
		{"1.2", "1.2.0", -1}, // Portage: an implicit component sorts below an explicit ".0"
		{"1.2.3-r1", "1.2.3-r2", -1},
		{"1.2.3-r2", "1.2.3-r1", 1},
		{"1.2.3", "1.2.3-r1", -1}, // implicit -r0 < -r1
		{"1.2b", "1.2c", -1},
		{"1.2c", "1.2b", 1},
		{"1.0_alpha1", "1.0_beta1", -1},
		{"1.0_beta1", "1.0_pre1", -1},
		{"1.0_pre1", "1.0_rc1", -1},
		{"1.0_rc1", "1.0", -1}, // rc < no suffix
		{"1.0", "1.0_p1", -1},  // no suffix < _p
		{"1.0_p1", "1.0_p2", -1},
		{"255.4-r2", "255.4-r2", 0},
		// Leading zeros compare as decimal fractions, as in Portage's vercmp.
		{"1.02", "1.1", -1},
		{"1.010", "1.01", 0},
		{"1.01", "1.1", -1},
		{"1.1", "1.01", 1},
		{"01.2", "1.2", 0},
		// A letter beats a missing letter, but a further numeric component beats both.
		{"1.2", "1.2a", -1},
		{"12.2.5", "12.2b", 1},
		// Chained suffixes.
		{"1.0_rc1_p2", "1.0_rc1", 1},
		{"1.0_rc1_p2", "1.0_rc2", -1},
		{"1.0_alpha1_beta2", "1.0_alpha1", -1},
		{"1.0", "1.0_p0", -1},
		// Components too large for an int64.
		{"20251125", "20251124", 1},
		{"1.99999999999999999999", "1.99999999999999999998", 1},
		// Suffix numbers are unbounded too, and a missing suffix still sorts
		// below "_p0" while an empty or zero-padded number equals 0.
		{"1.0_p99999999999999999999", "1.0_p99999999999999999998", 1},
		{"1.0_p99999999999999999999", "1.0", 1},
		{"1.0_rc99999999999999999999", "1.0", -1},
		{"1.0_p", "1.0_p0", 0},
		{"1.0_p00", "1.0_p0", 0},
	}

	for _, tc := range cases {
		got, err := Compare(tc.a, tc.b)
		if err != nil {
			t.Fatalf("Compare(%q, %q) returned error: %v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareInvalid(t *testing.T) {
	if _, err := Compare("not-a-version!!", "1.0"); err == nil {
		t.Error("expected error for unparseable version, got nil")
	}
}

func TestSatisfies(t *testing.T) {
	cases := []struct {
		installed, op, constraint string
		want                      bool
	}{
		{"2.0.7", "ge", "2.0.6", true},
		{"2.0.5", "ge", "2.0.6", false},
		{"2.0.6", "lt", "2.0.6", false},
		{"2.0.5", "lt", "2.0.6", true},
		{"3.18.1", "ge", "3.18.1", true},
		{"3.18.0", "ge", "3.18.1", false},
		{"2.4.5", "eq", "2.4*", true},
		{"2.5.0", "eq", "2.4*", false},
		{"1.0", "eq", "1.0", true},
		// "=*" glob matches on component boundaries only (Gentoo bug 560466).
		{"2.4", "eq", "2.4*", true},
		{"2.4-r3", "eq", "2.4*", true},
		{"2.4_rc1", "eq", "2.4*", true},
		{"2.4a", "eq", "2.4*", true},
		{"2.40", "eq", "2.4*", false},
		{"2.45.1", "eq", "2.4*", false},
		{"1.0", "eq", "1*", true},
		{"10.0", "eq", "1*", false},
		// Revision-only operators require the same base version.
		{"1.0-r2", "rge", "1.0-r1", true},
		{"1.0-r1", "rge", "1.0-r1", true},
		{"1.0", "rge", "1.0-r1", false},
		{"1.5", "rge", "1.0-r1", false},
		{"1.0-r2", "rgt", "1.0-r1", true},
		{"1.0-r1", "rgt", "1.0-r1", false},
		{"2.0", "rgt", "1.0-r1", false},
		{"1.0-r3", "rle", "1.0-r3", true},
		{"1.0-r4", "rle", "1.0-r3", false},
		{"0.9", "rle", "1.0-r3", false},
		{"1.0", "rlt", "1.0-r1", true},
		{"1.0-r1", "rlt", "1.0-r1", false},
		{"0.5", "rlt", "1.0-r1", false},
	}

	for _, tc := range cases {
		got, err := Satisfies(tc.installed, tc.op, tc.constraint)
		if err != nil {
			t.Fatalf("Satisfies(%q, %q, %q) returned error: %v", tc.installed, tc.op, tc.constraint, err)
		}
		if got != tc.want {
			t.Errorf("Satisfies(%q, %q, %q) = %v, want %v", tc.installed, tc.op, tc.constraint, got, tc.want)
		}
	}
}

func TestSatisfiesUnsupportedOp(t *testing.T) {
	if _, err := Satisfies("1.0", "bogus", "1.0"); err == nil {
		t.Error("expected error for unsupported operator, got nil")
	}
}

func TestSatisfiesInvalidGlob(t *testing.T) {
	for _, constraint := range []string{"*", "x.y*"} {
		if _, err := Satisfies("1.0", "eq", constraint); err == nil {
			t.Errorf("Satisfies(1.0, eq, %q): expected error, got nil", constraint)
		}
	}
}
