package vault

import (
	"testing"
)

// TestMergeStrategy_Constants ensures the iota values remain stable so that
// persisted strategy values (e.g. in scripts) don't silently change meaning.
func TestMergeStrategy_Constants(t *testing.T) {
	if MergeStrategySkip != 0 {
		t.Errorf("MergeStrategySkip should be 0, got %d", MergeStrategySkip)
	}
	if MergeStrategyOverwrite != 1 {
		t.Errorf("MergeStrategyOverwrite should be 1, got %d", MergeStrategyOverwrite)
	}
}

func TestMergeResult_ZeroValue(t *testing.T) {
	var r MergeResult
	if r.Added != nil {
		t.Errorf("zero-value Added should be nil")
	}
	if r.Skipped != nil {
		t.Errorf("zero-value Skipped should be nil")
	}
	if r.Overwritten != nil {
		t.Errorf("zero-value Overwritten should be nil")
	}
}

func TestMergeResult_Accumulation(t *testing.T) {
	r := MergeResult{}
	r.Added = append(r.Added, "KEY_A", "KEY_B")
	r.Skipped = append(r.Skipped, "KEY_C")
	r.Overwritten = append(r.Overwritten, "KEY_D")

	if len(r.Added) != 2 {
		t.Errorf("expected 2 added, got %d", len(r.Added))
	}
	if len(r.Skipped) != 1 {
		t.Errorf("expected 1 skipped, got %d", len(r.Skipped))
	}
	if len(r.Overwritten) != 1 {
		t.Errorf("expected 1 overwritten, got %d", len(r.Overwritten))
	}
}

func TestMergeResult_TotalCount(t *testing.T) {
	r := MergeResult{
		Added:       []string{"A", "B"},
		Skipped:     []string{"C"},
		Overwritten: []string{"D", "E", "F"},
	}
	total := len(r.Added) + len(r.Skipped) + len(r.Overwritten)
	if total != 6 {
		t.Errorf("expected total 6, got %d", total)
	}
}
