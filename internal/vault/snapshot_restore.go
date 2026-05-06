package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
)

// RestoreSnapshot decrypts a snapshot file and writes it back as the active
// encrypted vault file, overwriting any existing sealed file.
func (v *Vault) RestoreSnapshot(snapshotID string, identity age.Identity) error {
	dir := snapshotDir(v.dir)
	snapPath := filepath.Join(dir, snapshotID+".age")

	if _, err := os.Stat(snapPath); os.IsNotExist(err) {
		return fmt.Errorf("snapshot %q not found", snapshotID)
	}

	// Verify we can decrypt the snapshot before overwriting anything.
	tmpFile, err := os.CreateTemp("", "envault-restore-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	tmpFile.Close()

	if err := DecryptFile(snapPath, tmpPath, identity); err != nil {
		return fmt.Errorf("decrypt snapshot: %w", err)
	}

	dest := encryptedPath(v.dir, v.name)

	// Back up existing sealed file if present.
	if _, err := os.Stat(dest); err == nil {
		backup := dest + ".bak"
		if err := copyFile(dest, backup); err != nil {
			return fmt.Errorf("backup existing vault: %w", err)
		}
	}

	if err := copyFile(snapPath, dest); err != nil {
		return fmt.Errorf("restore snapshot to vault: %w", err)
	}

	_ = AppendAuditEvent(v.dir, AuditEvent{
		Timestamp: time.Now().UTC(),
		Operation: "restore",
		File:      v.name,
		Success:   true,
		Message:   fmt.Sprintf("restored from snapshot %s", snapshotID),
	})

	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
