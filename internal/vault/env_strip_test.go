package vault

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func generateStripTestIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func sealStripEnv(t *testing.T, dir, name, content string, rec age.Recipient) string {
	t.Helper()
	plain := filepath.Join(dir, name)
	enc := plain + ".age"
	if err := os.WriteFile(plain, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	v := &Vault{Dir: dir}
	if err := v.Seal(plain, []age.Recipient{rec}); err != nil {
		t.Fatalf("seal: %v", err)
	}
	_ = os.Remove(plain)
	return enc
}

func TestStrip_RemovesNamedKeys(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateStripTestIdentity(t)
	enc := sealStripEnv(t, dir, ".env", "FOO=1\nBAR=2\nBAZ=3\n", rec)

	res, err := Strip(dir, enc, id, []age.Recipient{rec}, StripOptions{Keys: []string{"BAR"}})
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "BAR" {
		t.Errorf("expected [BAR] removed, got %v", res.Removed)
	}
	if res.Retained != 2 {
		t.Errorf("expected 2 retained, got %d", res.Retained)
	}

	pairs, err := decryptEnvPairs(enc, id)
	if err != nil {
		t.Fatalf("decrypt after strip: %v", err)
	}
	for _, p := range pairs {
		if p.Key == "BAR" {
			t.Error("BAR should have been stripped")
		}
	}
}

func TestStrip_RemovesByPrefix(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateStripTestIdentity(t)
	enc := sealStripEnv(t, dir, ".env", "DEBUG_A=1\nDEBUG_B=2\nPROD_C=3\n", rec)

	res, err := Strip(dir, enc, id, []age.Recipient{rec}, StripOptions{Prefix: "DEBUG_"})
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if len(res.Removed) != 2 {
		t.Errorf("expected 2 removed, got %d", len(res.Removed))
	}
	if res.Retained != 1 {
		t.Errorf("expected 1 retained, got %d", res.Retained)
	}
}

func TestStrip_NoMatch_Noop(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateStripTestIdentity(t)
	enc := sealStripEnv(t, dir, ".env", "FOO=1\nBAR=2\n", rec)

	res, err := Strip(dir, enc, id, []age.Recipient{rec}, StripOptions{Keys: []string{"MISSING"}})
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if len(res.Removed) != 0 {
		t.Errorf("expected nothing removed, got %v", res.Removed)
	}
	if res.Retained != 2 {
		t.Errorf("expected 2 retained, got %d", res.Retained)
	}
}

func TestStrip_WrongSuffix_Error(t *testing.T) {
	dir := t.TempDir()
	id, rec := generateStripTestIdentity(t)
	_, err := Strip(dir, filepath.Join(dir, ".env"), id, []age.Recipient{rec}, StripOptions{})
	if err == nil {
		t.Error("expected error for non-.age file")
	}
}
