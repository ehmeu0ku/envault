package vault

import (
	"testing"
)

func TestApplyMask_FullMask(t *testing.T) {
	got := applyMask("secret", 0)
	if got != "******" {
		t.Errorf("want ******, got %s", got)
	}
}

func TestApplyMask_EmptyValue(t *testing.T) {
	got := applyMask("", 0)
	if got != "****" {
		t.Errorf("want ****, got %s", got)
	}
}

func TestApplyMask_PartialReveal(t *testing.T) {
	got := applyMask("abcdef", 3)
	if got != "abc***" {
		t.Errorf("want abc***, got %s", got)
	}
}

func TestApplyMask_RevealExceedsLength(t *testing.T) {
	got := applyMask("ab", 10)
	if got != "**" {
		t.Errorf("want **, got %s", got)
	}
}

func TestShouldMaskKey_EmptyFilter(t *testing.T) {
	if !shouldMaskKey("ANY_KEY", nil, "") {
		t.Error("empty filter should mask all keys")
	}
}

func TestShouldMaskKey_ExplicitMatch(t *testing.T) {
	set := map[string]bool{"SECRET": true}
	if !shouldMaskKey("SECRET", set, "") {
		t.Error("SECRET should be masked")
	}
	if shouldMaskKey("OTHER", set, "") {
		t.Error("OTHER should not be masked")
	}
}

func TestShouldMaskKey_PrefixMatch(t *testing.T) {
	if !shouldMaskKey("DB_PASS", nil, "DB_") {
		t.Error("DB_PASS should match DB_ prefix")
	}
	if shouldMaskKey("APP_NAME", nil, "DB_") {
		t.Error("APP_NAME should not match DB_ prefix")
	}
}

func TestMaskResult_ZeroValue(t *testing.T) {
	var r MaskResult
	if r.Masked != 0 || r.Skipped != 0 {
		t.Error("zero value should have no masked or skipped")
	}
}

func TestMaskOptions_Defaults(t *testing.T) {
	var opts MaskOptions
	if opts.Reveal != 0 {
		t.Error("default reveal should be 0")
	}
	if len(opts.Keys) != 0 {
		t.Error("default keys should be empty")
	}
}
