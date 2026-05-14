package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generatePromoteTestIdentity(t *testing.T) (*age.X25519Identity, *age.X25519Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func setupPromoteVault(t *testing.T, v *Vault, envFile, content string, id *age.X25519Identity, rec *age.X25519Recipient) {
	t.Helper()
	plainPath := filepath.Join(v.Dir, envFile)
	if err := os.WriteFile(plainPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	if err := v.Seal(envFile, id.Recipient()); err != nil {
		t.Fatalf("seal: %v", err)
	}
}

func TestPromote_AddsNewKeys(t *testing.T) {
	v := tempVault(t)
	id, rec := generatePromoteTestIdentity(t)

	setupPromoteVault(t, v, ".env.staging", "DB_HOST=staging-db\nAPI_KEY=stg123\n", id, rec)
	setupPromoteVault(t, v, ".env.production", "DB_HOST=prod-db\n", id, rec)

	result, err := v.Promote(".env.staging", ".env.production", id, []age.Recipient{rec}, false)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	if result.Added != 1 {
		t.Errorf("expected 1 added, got %d", result.Added)
	}
	if result.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", result.Skipped)
	}
}

func TestPromote_OverwriteExistingKeys(t *testing.T) {
	v := tempVault(t)
	id, rec := generatePromoteTestIdentity(t)

	setupPromoteVault(t, v, ".env.staging", "DB_HOST=staging-db\n", id, rec)
	setupPromoteVault(t, v, ".env.production", "DB_HOST=prod-db\n", id, rec)

	result, err := v.Promote(".env.staging", ".env.production", id, []age.Recipient{rec}, true)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	if result.Added != 1 {
		t.Errorf("expected 1 added (overwrite), got %d", result.Added)
	}
	if result.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", result.Skipped)
	}

	// Verify the value was overwritten
	pairs, err := decryptEnvPairs(encryptedPath(filepath.Join(v.Dir, ".env.production")), id)
	if err != nil {
		t.Fatalf("decrypt result: %v", err)
	}
	if pairs["DB_HOST"] != "staging-db" {
		t.Errorf("expected DB_HOST=staging-db, got %s", pairs["DB_HOST"])
	}
}

func TestPromote_MissingSourceFile(t *testing.T) {
	v := tempVault(t)
	id, rec := generatePromoteTestIdentity(t)

	_, err := v.Promote(".env.staging", ".env.production", id, []age.Recipient{rec}, false)
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestPromote_FreshDestination(t *testing.T) {
	v := tempVault(t)
	id, rec := generatePromoteTestIdentity(t)

	setupPromoteVault(t, v, ".env.staging", "FOO=bar\nBAZ=qux\n", id, rec)

	result, err := v.Promote(".env.staging", ".env.production", id, []age.Recipient{rec}, false)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	if result.Added != 2 {
		t.Errorf("expected 2 added, got %d", result.Added)
	}
	if result.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", result.Skipped)
	}
}
