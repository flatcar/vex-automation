package portage

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.0.6", "2.0.6", 0},
		{"2.0.5", "2.0.6", -1},
		{"2.0.7", "2.0.6", 1},
		{"1.2", "1.2.0", 0}, // missing trailing components treated as 0
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
