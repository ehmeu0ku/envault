package vault

import (
	"testing"
)

func TestStripQuotes_DoubleQuotes(t *testing.T) {
	got := stripQuotes(`"hello"`)
	if got != "hello" {
		t.Errorf("expected hello, got %q", got)
	}
}

func TestStripQuotes_SingleQuotes(t *testing.T) {
	got := stripQuotes("'world'")
	if got != "world" {
		t.Errorf("expected world, got %q", got)
	}
}

func TestStripQuotes_NoQuotes(t *testing.T) {
	got := stripQuotes("plain")
	if got != "plain" {
		t.Errorf("expected plain, got %q", got)
	}
}

func TestStripQuotes_MismatchedQuotes(t *testing.T) {
	got := stripQuotes(`"mismatch'`)
	if got != `"mismatch'` {
		t.Errorf("expected unchanged, got %q", got)
	}
}

func TestStripQuotes_EmptyString(t *testing.T) {
	got := stripQuotes("")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestStripQuotes_SingleChar(t *testing.T) {
	got := stripQuotes("x")
	if got != "x" {
		t.Errorf("expected x, got %q", got)
	}
}

func TestTrimResult_ZeroValue(t *testing.T) {
	var r TrimResult
	if r.Trimmed != 0 || r.Unquoted != 0 || r.Renamed != 0 {
		t.Error("expected zero value TrimResult")
	}
}

func TestTrimResult_Accumulation(t *testing.T) {
	r := TrimResult{Trimmed: 3, Unquoted: 1, Renamed: 2}
	if r.Trimmed+r.Unquoted+r.Renamed != 6 {
		t.Errorf("unexpected total: %d", r.Trimmed+r.Unquoted+r.Renamed)
	}
}

func TestTrimOptions_Defaults(t *testing.T) {
	var opts TrimOptions
	if opts.TrimSpace || opts.RemoveQuotes || opts.NormalizeKeys {
		t.Error("expected all options false by default")
	}
}
