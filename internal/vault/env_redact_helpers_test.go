package vault

import (
	"testing"
)

func TestRedactKey_FullObfuscation(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"A", "A"},
		{"AB", "AB"},
		{"ABC", "A*C"},
		{"SECRET", "S****T"},
		{"DATABASE_URL", "D*********L"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := redactKey(tc.input)
			if got != tc.want {
				t.Errorf("redactKey(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestMaskValue_NonEmpty(t *testing.T) {
	cases := []struct {
		input string
		mask  string
	}{
		{"hunter2", "*"},
		{"supersecret", "#"},
		{"x", "-"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := maskValue(tc.input, tc.mask)
			if got == tc.input {
				t.Errorf("maskValue(%q) should not equal original value", tc.input)
			}
			if got == "" {
				t.Errorf("maskValue(%q) should not be empty for non-empty input", tc.input)
			}
		})
	}
}

func TestRedactOptions_Defaults(t *testing.T) {
	opts := RedactOptions{}
	if opts.MaskChar != "" {
		t.Errorf("default MaskChar should be empty string (resolved at call time)")
	}
	if opts.ShowKeys {
		t.Errorf("default ShowKeys should be false")
	}
	if len(opts.RevealKeys) != 0 {
		t.Errorf("default RevealKeys should be nil/empty")
	}
}

func TestRedactResult_Empty(t *testing.T) {
	r := &RedactResult{}
	if len(r.Lines) != 0 {
		t.Errorf("new RedactResult should have no lines")
	}
}
