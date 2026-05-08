package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateProfileTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestActiveProfile_EmptyOnMissing(t *testing.T) {
	dir, _ := os.MkdirTemp("", "envault-profile-sw-*")
	defer os.RemoveAll(dir)

	active, err := ActiveProfile(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if active != "" {
		t.Errorf("expected empty active profile, got %q", active)
	}
}

func TestSetAndGetActiveProfile(t *testing.T) {
	dir, _ := os.MkdirTemp("", "envault-profile-sw-*")
	defer os.RemoveAll(dir)

	if err := SetActiveProfile(dir, "staging"); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}
	active, err := ActiveProfile(dir)
	if err != nil {
		t.Fatalf("ActiveProfile: %v", err)
	}
	if active != "staging" {
		t.Errorf("expected 'staging', got %q", active)
	}
}

func TestSwitchProfile_MissingProfile(t *testing.T) {
	dir, _ := os.MkdirTemp("", "envault-profile-sw-*")
	defer os.RemoveAll(dir)

	err := SwitchProfile(dir, "ghost", "/tmp/id.txt", ".env")
	if err == nil {
		t.Error("expected error for missing profile")
	}
}

func TestSwitchProfile_MissingEncryptedFile(t *testing.T) {
	dir, _ := os.MkdirTemp("", "envault-profile-sw-*")
	defer os.RemoveAll(dir)

	_ = AddProfile(dir, "dev", filepath.Join(dir, ".env.dev"))

	err := SwitchProfile(dir, "dev", "/tmp/id.txt", filepath.Join(dir, ".env"))
	if err == nil {
		t.Error("expected error when encrypted file is missing")
	}
}

func TestSetActiveProfile_FilePermissions(t *testing.T) {
	dir, _ := os.MkdirTemp("", "envault-profile-sw-*")
	defer os.RemoveAll(dir)

	_ = SetActiveProfile(dir, "prod")
	info, err := os.Stat(filepath.Join(dir, ".envault_active_profile"))
	if err != nil {
		t.Fatalf("stat marker: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600, got %v", info.Mode().Perm())
	}
}
