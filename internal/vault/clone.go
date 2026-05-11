package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// Clone decrypts a sealed vault file using srcIdentity, then re-encrypts it
// for dstRecipients and writes the result to dstPath. It is useful for
// duplicating a vault entry into a new environment or directory.
func Clone(srcPath string, srcIdentity *age.X25519Identity, dstPath string, dstRecipients []age.Recipient) error {
	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		return fmt.Errorf("clone: source file not found: %s", srcPath)
	}

	if len(dstRecipients) == 0 {
		return fmt.Errorf("clone: at least one destination recipient is required")
	}

	// Decrypt source into a temp file
	tmpFile, err := os.CreateTemp("", "envault-clone-*.env")
	if err != nil {
		return fmt.Errorf("clone: create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := DecryptFile(srcPath, tmpPath, srcIdentity); err != nil {
		return fmt.Errorf("clone: decrypt source: %w", err)
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(dstPath), 0700); err != nil {
		return fmt.Errorf("clone: create destination directory: %w", err)
	}

	// Encrypt to destination
	if err := EncryptFile(tmpPath, dstPath, dstRecipients); err != nil {
		return fmt.Errorf("clone: encrypt to destination: %w", err)
	}

	return nil
}

// cloneRawFile copies a file byte-for-byte (used internally for raw copies).
func cloneRawFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
