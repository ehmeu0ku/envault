package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// ScopeOptions controls how scoping is applied.
type ScopeOptions struct {
	Prefix    string // e.g. "prod", "staging"
	Overwrite bool
}

// ScopeResult summarises what Scope did.
type ScopeResult struct {
	Added    int
	Skipped  int
	Total    int
}

// Scope reads an encrypted .env file, prefixes every key with opts.Prefix,
// and writes the result to destPath (re-encrypted for recipients).
func Scope(vaultDir, srcPath, destPath string, recipients []age.Recipient, identity age.Identity, opts ScopeOptions) (ScopeResult, error) {
	if opts.Prefix == "" {
		return ScopeResult{}, fmt.Errorf("scope: prefix must not be empty")
	}

	encSrc := encryptedPath(srcPath)
	if _, err := os.Stat(encSrc); err != nil {
		return ScopeResult{}, fmt.Errorf("scope: encrypted source not found: %w", err)
	}

	pairs, err := decryptEnvPairs(encSrc, identity)
	if err != nil {
		return ScopeResult{}, fmt.Errorf("scope: decrypt: %w", err)
	}

	var result ScopeResult
	result.Total = len(pairs)

	prefix := strings.ToUpper(opts.Prefix) + "_"

	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts := strings.SplitN(p, "=", 2)
		if len(parts) != 2 {
			continue
		}
		newKey := prefix + parts[0]
		out = append(out, newKey+"="+parts[1])
		result.Added++
	}

	encDest := encryptedPath(destPath)
	if !opts.Overwrite {
		if _, err := os.Stat(encDest); err == nil {
			return ScopeResult{}, fmt.Errorf("scope: destination already exists: %s", encDest)
		}
	}

	if err := os.MkdirAll(filepath.Dir(encDest), 0700); err != nil {
		return ScopeResult{}, fmt.Errorf("scope: mkdir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(encDest), ".scope-*")
	if err != nil {
		return ScopeResult{}, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	plain := []byte(strings.Join(out, "\n") + "\n")
	if err := os.WriteFile(tmp.Name(), plain, 0600); err != nil {
		return ScopeResult{}, err
	}

	if err := EncryptFile(tmp.Name(), encDest, recipients); err != nil {
		return ScopeResult{}, fmt.Errorf("scope: encrypt: %w", err)
	}

	return result, nil
}
