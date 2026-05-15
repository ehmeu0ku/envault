package vault

import (
	"fmt"
	"strings"

	"github.com/nicholasgasior/envault/internal/crypto"
	"filippo.io/age"
)

// SetDefaultOptions controls behaviour of SetDefault.
type SetDefaultOptions struct {
	// Overwrite replaces existing values with the provided defaults.
	Overwrite bool
}

// SetDefaultResult summarises what SetDefault did.
type SetDefaultResult struct {
	Set     []string
	Skipped []string
}

// SetDefault decrypts the vault at encPath, fills in any missing keys from
// defaults, then re-encrypts in place. If opts.Overwrite is true, existing
// values are replaced as well.
func SetDefault(
	vaultDir string,
	encPath string,
	defaults map[string]string,
	identity age.Identity,
	recipient age.Recipient,
	opts SetDefaultOptions,
) (SetDefaultResult, error) {
	if !strings.HasSuffix(encPath, ".age") {
		return SetDefaultResult{}, fmt.Errorf("setdefault: expected .age file, got %q", encPath)
	}

	pairs, err := decryptEnvPairs(encPath, identity)
	if err != nil {
		return SetDefaultResult{}, fmt.Errorf("setdefault: decrypt: %w", err)
	}

	existing := make(map[string]string, len(pairs))
	for _, p := range pairs {
		existing[p[0]] = p[1]
	}

	var result SetDefaultResult
	for k, v := range defaults {
		if _, found := existing[k]; found && !opts.Overwrite {
			result.Skipped = append(result.Skipped, k)
			continue
		}
		existing[k] = v
		result.Set = append(result.Set, k)
	}

	// Rebuild ordered pairs: keep original order, append new keys.
	seen := make(map[string]bool)
	var out []string
	for _, p := range pairs {
		seen[p[0]] = true
		out = append(out, fmt.Sprintf("%s=%s", p[0], existing[p[0]]))
	}
	for k, v := range defaults {
		if !seen[k] {
			out = append(out, fmt.Sprintf("%s=%s", k, v))
		}
	}

	data := []byte(strings.Join(out, "\n") + "\n")
	if err := crypto.EncryptFile(data, encPath, recipient); err != nil {
		return SetDefaultResult{}, fmt.Errorf("setdefault: encrypt: %w", err)
	}

	return result, nil
}
