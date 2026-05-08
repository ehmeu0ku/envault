package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func tempProfileDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "envault-profile-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestLoadProfiles_EmptyOnMissing(t *testing.T) {
	dir := tempProfileDir(t)
	idx, err := LoadProfiles(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(idx) != 0 {
		t.Errorf("expected empty index, got %d entries", len(idx))
	}
}

func TestAddProfile_CreatesEntry(t *testing.T) {
	dir := tempProfileDir(t)
	if err := AddProfile(dir, "dev", ".env.dev"); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}
	idx, err := LoadProfiles(dir)
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	p, ok := idx["dev"]
	if !ok {
		t.Fatal("expected 'dev' profile to exist")
	}
	if p.EnvFile != ".env.dev" {
		t.Errorf("expected env file '.env.dev', got %q", p.EnvFile)
	}
	if p.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestAddProfile_UpdatesExisting(t *testing.T) {
	dir := tempProfileDir(t)
	_ = AddProfile(dir, "staging", ".env.staging")
	_ = AddProfile(dir, "staging", ".env.staging.new")
	p, err := GetProfile(dir, "staging")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if p.EnvFile != ".env.staging.new" {
		t.Errorf("expected updated env file, got %q", p.EnvFile)
	}
}

func TestRemoveProfile_DeletesEntry(t *testing.T) {
	dir := tempProfileDir(t)
	_ = AddProfile(dir, "prod", ".env.prod")
	if err := RemoveProfile(dir, "prod"); err != nil {
		t.Fatalf("RemoveProfile: %v", err)
	}
	_, err := GetProfile(dir, "prod")
	if err == nil {
		t.Error("expected error after removal")
	}
}

func TestRemoveProfile_NotFound(t *testing.T) {
	dir := tempProfileDir(t)
	err := RemoveProfile(dir, "ghost")
	if err == nil {
		t.Error("expected error for missing profile")
	}
}

func TestSaveAndLoadProfiles_Roundtrip(t *testing.T) {
	dir := tempProfileDir(t)
	_ = AddProfile(dir, "dev", ".env.dev")
	_ = AddProfile(dir, "prod", ".env.prod")
	idx, err := LoadProfiles(dir)
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	if len(idx) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(idx))
	}
	info, err := os.Stat(filepath.Join(dir, ".envault_profiles.json"))
	if err != nil {
		t.Fatalf("stat profile index: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %v", info.Mode().Perm())
	}
}
