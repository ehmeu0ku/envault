package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func tempLockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "envault-lock-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestAcquireLock_CreatesFile(t *testing.T) {
	dir := tempLockDir(t)

	if err := AcquireLock(dir); err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}

	lp := filepath.Join(dir, lockFileName)
	if _, err := os.Stat(lp); err != nil {
		t.Fatalf("lock file not created: %v", err)
	}
}

func TestIsLocked_TrueAfterAcquire(t *testing.T) {
	dir := tempLockDir(t)

	if IsLocked(dir) {
		t.Fatal("expected not locked before acquire")
	}

	if err := AcquireLock(dir); err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}

	if !IsLocked(dir) {
		t.Fatal("expected locked after acquire")
	}
}

func TestReleaseLock_RemovesFile(t *testing.T) {
	dir := tempLockDir(t)

	if err := AcquireLock(dir); err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if err := ReleaseLock(dir); err != nil {
		t.Fatalf("ReleaseLock: %v", err)
	}

	if IsLocked(dir) {
		t.Fatal("expected not locked after release")
	}
}

func TestReleaseLock_NoopIfMissing(t *testing.T) {
	dir := tempLockDir(t)

	if err := ReleaseLock(dir); err != nil {
		t.Fatalf("ReleaseLock on missing lock should not error: %v", err)
	}
}

func TestAcquireLock_FailsIfAlreadyLocked(t *testing.T) {
	dir := tempLockDir(t)

	if err := AcquireLock(dir); err != nil {
		t.Fatalf("first AcquireLock: %v", err)
	}

	// Second acquire by the same process — processAlive(os.Getpid()) is true,
	// so it should be rejected.
	if err := AcquireLock(dir); err == nil {
		t.Fatal("expected error on second acquire, got nil")
	}
}

func TestAcquireLock_StaleLockIsReplaced(t *testing.T) {
	dir := tempLockDir(t)

	// Write a lock file with a PID that cannot be alive (PID 0 is invalid).
	staleLock := LockInfo{PID: 0}
	data, _ := jsonMarshal(staleLock)
	lp := filepath.Join(dir, lockFileName)
	if err := os.WriteFile(lp, data, 0600); err != nil {
		t.Fatalf("write stale lock: %v", err)
	}

	if err := AcquireLock(dir); err != nil {
		t.Fatalf("AcquireLock over stale lock: %v", err)
	}
}
