package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const lockFileName = ".envault.lock"

// LockInfo holds metadata about an active lock.
type LockInfo struct {
	PID       int       `json:"pid"`
	LockedAt  time.Time `json:"locked_at"`
	VaultPath string    `json:"vault_path"`
}

func lockPath(vaultDir string) string {
	return filepath.Join(vaultDir, lockFileName)
}

// AcquireLock creates a lock file in vaultDir. Returns an error if a lock
// already exists and the owning process is still alive.
func AcquireLock(vaultDir string) error {
	lp := lockPath(vaultDir)

	if _, err := os.Stat(lp); err == nil {
		// Lock file exists — check if the owning PID is still alive.
		data, readErr := os.ReadFile(lp)
		if readErr == nil {
			var info LockInfo
			if jsonErr := jsonUnmarshal(data, &info); jsonErr == nil {
				if processAlive(info.PID) {
					return fmt.Errorf("vault is locked by PID %d (since %s)",
						info.PID, info.LockedAt.Format(time.RFC3339))
				}
				// Stale lock — remove it.
				_ = os.Remove(lp)
			}
		}
	}

	info := LockInfo{
		PID:       os.Getpid(),
		LockedAt:  time.Now().UTC(),
		VaultPath: vaultDir,
	}
	data, err := jsonMarshal(info)
	if err != nil {
		return fmt.Errorf("marshal lock info: %w", err)
	}
	if err := os.WriteFile(lp, data, 0600); err != nil {
		return fmt.Errorf("write lock file: %w", err)
	}
	return nil
}

// ReleaseLock removes the lock file from vaultDir. It is a no-op if no lock
// exists.
func ReleaseLock(vaultDir string) error {
	lp := lockPath(vaultDir)
	if err := os.Remove(lp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove lock file: %w", err)
	}
	return nil
}

// IsLocked reports whether vaultDir currently has an active lock file.
func IsLocked(vaultDir string) bool {
	_, err := os.Stat(lockPath(vaultDir))
	return err == nil
}

// processAlive returns true when a process with the given PID exists.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds; sending signal 0 checks existence.
	err = proc.Signal(os.Signal(nil))
	return err == nil
}
