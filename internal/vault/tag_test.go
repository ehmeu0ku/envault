package vault

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func tempTagDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "envault-tag-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestLoadTags_EmptyOnMissing(t *testing.T) {
	dir := tempTagDir(t)
	idx, err := LoadTags(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(idx) != 0 {
		t.Errorf("expected empty index, got %v", idx)
	}
}

func TestSaveAndLoadTags_Roundtrip(t *testing.T) {
	dir := tempTagDir(t)
	idx := make(tagIndex)
	AddTag(idx, "prod.env.age", "production")
	AddTag(idx, "prod.env.age", "backend")
	AddTag(idx, "dev.env.age", "development")

	if err := SaveTags(dir, idx); err != nil {
		t.Fatalf("SaveTags: %v", err)
	}

	loaded, err := LoadTags(dir)
	if err != nil {
		t.Fatalf("LoadTags: %v", err)
	}
	if len(loaded["prod.env.age"]) != 2 {
		t.Errorf("expected 2 tags for prod.env.age, got %v", loaded["prod.env.age"])
	}
	if len(loaded["dev.env.age"]) != 1 {
		t.Errorf("expected 1 tag for dev.env.age, got %v", loaded["dev.env.age"])
	}
}

func TestAddTag_NoDuplicates(t *testing.T) {
	idx := make(tagIndex)
	AddTag(idx, "a.env.age", "staging")
	AddTag(idx, "a.env.age", "staging")
	if len(idx["a.env.age"]) != 1 {
		t.Errorf("expected 1 tag, got %d", len(idx["a.env.age"]))
	}
}

func TestRemoveTag(t *testing.T) {
	idx := make(tagIndex)
	AddTag(idx, "b.env.age", "alpha")
	AddTag(idx, "b.env.age", "beta")
	RemoveTag(idx, "b.env.age", "alpha")
	if slices.Contains(idx["b.env.age"], "alpha") {
		t.Error("expected alpha to be removed")
	}
	if !slices.Contains(idx["b.env.age"], "beta") {
		t.Error("expected beta to remain")
	}
}

func TestFindByTag(t *testing.T) {
	idx := make(tagIndex)
	AddTag(idx, "x.env.age", "production")
	AddTag(idx, "y.env.age", "production")
	AddTag(idx, "z.env.age", "development")

	results := FindByTag(idx, "production")
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r == "z.env.age" {
			t.Error("z.env.age should not be in production results")
		}
	}
}

func TestSaveTags_FilePermissions(t *testing.T) {
	dir := tempTagDir(t)
	idx := make(tagIndex)
	AddTag(idx, "secure.env.age", "secret")
	if err := SaveTags(dir, idx); err != nil {
		t.Fatalf("SaveTags: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, tagFileName))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %v", info.Mode().Perm())
	}
}
