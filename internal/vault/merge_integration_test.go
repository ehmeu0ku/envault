package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicholasgasior/envault/internal/crypto"
)

// TestMerge_ResultIsDecryptable verifies that after a merge the destination
// file can be decrypted and contains the expected merged content.
func TestMerge_ResultIsDecryptable(t *testing.T) {
	id, rec := generateMergeTestIdentity(t)
	v, _ := setupMergeVault(t, id, rec)

	writeSealedEnv(t, v, ".env", "NEW_KEY=hello\n", rec)
	writeSealedEnv(t, v, ".env.prod", "EXISTING_KEY=world\n", rec)

	_, err := v.Merge(".env", ".env.prod", id, rec, MergeStrategySkip)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	out := filepath.Join(t.TempDir(), "merged.env")
	if err := crypto.DecryptFile(encryptedPath(filepath.Join(v.dir, ".env.prod")), out, id); err != nil {
		t.Fatalf("decrypt merged: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read merged: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "NEW_KEY=hello") {
		t.Errorf("merged file missing NEW_KEY, got:\n%s", content)
	}
	if !strings.Contains(content, "EXISTING_KEY=world") {
		t.Errorf("merged file missing EXISTING_KEY, got:\n%s", content)
	}
}

// TestMerge_OverwriteChangesValue verifies the overwrite strategy updates
// the destination value and that the re-encrypted file reflects this.
func TestMerge_OverwriteChangesValue(t *testing.T) {
	id, rec := generateMergeTestIdentity(t)
	v, _ := setupMergeVault(t, id, rec)

	writeSealedEnv(t, v, ".env", "FOO=updated\n", rec)
	writeSealedEnv(t, v, ".env.prod", "FOO=original\n", rec)

	res, err := v.Merge(".env", ".env.prod", id, rec, MergeStrategyOverwrite)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(res.Overwritten) == 0 {
		t.Fatal("expected FOO to be overwritten")
	}

	out := filepath.Join(t.TempDir(), "result.env")
	if err := crypto.DecryptFile(encryptedPath(filepath.Join(v.dir, ".env.prod")), out, id); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "FOO=updated") {
		t.Errorf("expected FOO=updated in merged file, got:\n%s", data)
	}
}
