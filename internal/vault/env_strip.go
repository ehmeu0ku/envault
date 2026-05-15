package vault

import (
	"fmt"
	"strings"

	"filippo.io/age"

	"github.com/envault/envault/internal/crypto"
)

// StripOptions controls which keys are removed during a strip operation.
type StripOptions struct {
	// Keys is an explicit list of keys to remove.
	Keys []string
	// Prefix removes all keys that start with the given prefix.
	Prefix string
}

// StripResult summarises the outcome of a Strip call.
type StripResult struct {
	Removed []string
	Retained int
}

// Strip decrypts the sealed env file at encPath, removes matching keys,
// then re-encrypts in place using the provided recipients.
func Strip(vaultDir, encPath string, identity age.Identity, recipients []age.Recipient, opts StripOptions) (StripResult, error) {
	if !strings.HasSuffix(encPath, ".age") {
		return StripResult{}, fmt.Errorf("strip: expected .age file, got %q", encPath)
	}

	pairs, err := decryptEnvPairs(encPath, identity)
	if err != nil {
		return StripResult{}, fmt.Errorf("strip: decrypt: %w", err)
	}

	removeSet := make(map[string]bool, len(opts.Keys))
	for _, k := range opts.Keys {
		removeSet[k] = true
	}

	var kept []envPair
	var result StripResult

	for _, p := range pairs {
		shouldRemove := removeSet[p.Key]
		if !shouldRemove && opts.Prefix != "" {
			shouldRemove = strings.HasPrefix(p.Key, opts.Prefix)
		}
		if shouldRemove {
			result.Removed = append(result.Removed, p.Key)
		} else {
			kept = append(kept, p)
		}
	}

	result.Retained = len(kept)

	data := pairsToEnvBytes(kept)
	if err := crypto.EncryptFile(strings.NewReader(string(data)), encPath, recipients); err != nil {
		return StripResult{}, fmt.Errorf("strip: re-encrypt: %w", err)
	}

	return result, nil
}
