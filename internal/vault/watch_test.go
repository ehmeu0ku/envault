package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
)

func generateWatchTestIdentity(t *testing.T) (*age.X25519Identity, *age.X25519Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id, id.Recipient()
}

func TestHashFile_ChangesOnEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	if err := os.WriteFile(path, []byte("KEY=value1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h1, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}

	if err := os.WriteFile(path, []byte("KEY=value2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h2, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}

	if h1 == h2 {
		t.Error("expected hashes to differ after file edit")
	}
}

func TestHashFile_MissingFile(t *testing.T) {
	_, err := hashFile("/nonexistent/path/.env")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestWatch_DetectsChange(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, ".env")

	if err := os.WriteFile(plain, []byte("KEY=original\n"), 0600); err != nil {
		t.Fatal(err)
	}

	id, rec := generateWatchTestIdentity(t)

	// Pre-seal so the vault dir is valid.
	v := New(dir, []age.Recipient{rec}, []age.Identity{id})
	if err := v.Seal(plain); err != nil {
		t.Fatalf("initial seal: %v", err)
	}

	results := make(chan WatchResult, 4)
	done := make(chan struct{})

	go Watch(
		plain,
		20*time.Millisecond,
		[]age.Recipient{rec},
		[]age.Identity{id},
		func(r WatchResult) { results <- r },
		done,
	)

	// Modify the file to trigger detection.
	time.Sleep(30 * time.Millisecond)
	if err := os.WriteFile(plain, []byte("KEY=changed\n"), 0600); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-results:
		if !r.Changed {
			t.Error("expected Changed=true")
		}
		if r.Err != nil {
			t.Errorf("unexpected error: %v", r.Err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for change notification")
	}

	close(done)
}
