package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/subtlepseudonym/envault/internal/crypto"
	"filippo.io/age"
)

// PromoteResult holds the outcome of a promote operation.
type PromoteResult struct {
	SourceEnv string
	DestEnv   string
	Added     int
	Skipped   int
}

// Promote copies keys from a source environment vault into a destination
// environment vault, optionally overwriting existing keys. It re-encrypts
// all values for the destination recipients.
func (v *Vault) Promote(
	srcEnvFile string,
	dstEnvFile string,
	identity age.Identity,
	recipients []age.Recipient,
	overwrite bool,
) (PromoteResult, error) {
	srcPath := encryptedPath(srcEnvFile)
	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		return PromoteResult{}, fmt.Errorf("source encrypted file not found: %s", srcPath)
	}

	dstPath := encryptedPath(dstEnvFile)

	// Decrypt source
	srcPairs, err := decryptEnvPairs(srcPath, identity)
	if err != nil {
		return PromoteResult{}, fmt.Errorf("decrypt source: %w", err)
	}

	// Decrypt destination if it exists
	dstPairs := map[string]string{}
	if _, err := os.Stat(dstPath); err == nil {
		dstPairs, err = decryptEnvPairs(dstPath, identity)
		if err != nil {
			return PromoteResult{}, fmt.Errorf("decrypt destination: %w", err)
		}
	}

	result := PromoteResult{
		SourceEnv: srcEnvFile,
		DestEnv:   dstEnvFile,
	}

	for k, v := range srcPairs {
		if _, exists := dstPairs[k]; exists && !overwrite {
			result.Skipped++
			continue
		}
		dstPairs[k] = v
		result.Added++
	}

	// Write merged map back as env content
	content := pairsToEnvBytes(dstPairs)

	tmpFile, err := os.CreateTemp("", "envault-promote-*")
	if err != nil {
		return PromoteResult{}, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(content); err != nil {
		return PromoteResult{}, fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	if err := os.MkdirAll(filepath.Dir(dstPath), 0o700); err != nil {
		return PromoteResult{}, fmt.Errorf("create dest dir: %w", err)
	}

	if err := crypto.EncryptFile(tmpFile.Name(), dstPath, recipients); err != nil {
		return PromoteResult{}, fmt.Errorf("encrypt destination: %w", err)
	}

	return result, nil
}

func pairsToEnvBytes(pairs map[string]string) []byte {
	var buf []byte
	for k, v := range pairs {
		buf = append(buf, []byte(fmt.Sprintf("%s=%s\n", k, v))...)
	}
	return buf
}
