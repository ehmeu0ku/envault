package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateSearchTestIdentity(t *testing.T) age.Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestSearch_FindsByKey(t *testing.T) {
	dir := t.TempDir()
	v := tempVault(t, dir)
	id := generateSearchTestIdentity(t)

	writeEnvFile(t, filepath.Join(dir, ".env"), "DATABASE_URL=postgres://localhost/db\nSECRET_KEY=abc123\n")
	if err := v.Seal(filepath.Join(dir, ".env"), id.(age.Recipient)); err != nil {
		t.Fatalf("seal: %v", err)
	}

	results, err := v.Search(id, "DATABASE")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Key != "DATABASE_URL" {
		t.Errorf("expected key DATABASE_URL, got %s", results[0].Key)
	}
}

func TestSearch_FindsByValue(t *testing.T) {
	dir := t.TempDir()
	v := tempVault(t, dir)
	id := generateSearchTestIdentity(t)

	writeEnvFile(t, filepath.Join(dir, ".env"), "API_KEY=supersecret\nPORT=8080\n")
	if err := v.Seal(filepath.Join(dir, ".env"), id.(age.Recipient)); err != nil {
		t.Fatalf("seal: %v", err)
	}

	results, err := v.Search(id, "supersecret")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Value != "supersecret" {
		t.Errorf("expected value supersecret, got %s", results[0].Value)
	}
}

func TestSearch_NoMatch(t *testing.T) {
	dir := t.TempDir()
	v := tempVault(t, dir)
	id := generateSearchTestIdentity(t)

	writeEnvFile(t, filepath.Join(dir, ".env"), "FOO=bar\n")
	if err := v.Seal(filepath.Join(dir, ".env"), id.(age.Recipient)); err != nil {
		t.Fatalf("seal: %v", err)
	}

	results, err := v.Search(id, "NONEXISTENT")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSearch_EmptyVault(t *testing.T) {
	dir := t.TempDir()
	v := tempVault(t, dir)
	id := generateSearchTestIdentity(t)

	results, err := v.Search(id, "anything")
	if err != nil {
		t.Fatalf("search empty vault: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSearch_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	v := tempVault(t, dir)
	id := generateSearchTestIdentity(t)

	writeEnvFile(t, filepath.Join(dir, ".env"), "MY_TOKEN=HelloWorld\n")
	if err := v.Seal(filepath.Join(dir, ".env"), id.(age.Recipient)); err != nil {
		t.Fatalf("seal: %v", err)
	}

	results, err := v.Search(id, "helloworld")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}
