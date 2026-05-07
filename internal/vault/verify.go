package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nicholasgasior/envault/internal/crypto"
	"filippo.io/age"
)

// VerifyResult holds the result of verifying a single encrypted file.
type VerifyResult struct {
	Path    string
	OK      bool
	Message string
}

// Verify checks that an encrypted .env.age file can be successfully decrypted
// with the provided identity, confirming integrity without writing output.
func (v *Vault) Verify(envPath string, identity age.Identity) (VerifyResult, error) {
	encPath := encryptedPath(envPath)
	result := VerifyResult{Path: encPath}

	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		result.OK = false
		result.Message = fmt.Sprintf("encrypted file not found: %s", encPath)
		return result, nil
	}

	tmpFile, err := os.CreateTemp("", "envault-verify-*.env")
	if err != nil {
		return result, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := crypto.DecryptFile(encPath, tmpPath, identity); err != nil {
		result.OK = false
		result.Message = fmt.Sprintf("decryption failed: %s", err.Error())
		return result, nil
	}

	result.OK = true
	result.Message = "OK"
	return result, nil
}

// VerifyAll verifies all .env.age files found in the vault directory.
func (v *Vault) VerifyAll(identity age.Identity) ([]VerifyResult, error) {
	entries, err := v.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list vault entries: %w", err)
	}

	var results []VerifyResult
	for _, entry := range entries {
		// Derive the plain path from the encrypted path by stripping .age suffix
		plainPath := entry.EncryptedPath[:len(entry.EncryptedPath)-len(".age")]
		_ = filepath.Clean(plainPath)

		res, err := v.Verify(plainPath, identity)
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}
