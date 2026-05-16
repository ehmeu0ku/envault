package vault

import (
	"fmt"
	"strings"

	"filippo.io/age"

	"github.com/vercel/envault/internal/crypto"
)

// SelectOptions controls which keys are extracted from the vault.
type SelectOptions struct {
	Keys     []string // explicit keys to include
	Prefixes []string // include keys matching any prefix
	Invert   bool     // if true, exclude matched keys instead
}

// SelectResult holds the outcome of a Select operation.
type SelectResult struct {
	Included int
	Excluded int
}

// Select decrypts the vault at encPath, filters key/value pairs according to
// opts, re-encrypts the result back to outPath for the given recipients.
func Select(vaultDir, encPath, outPath string, recipients []age.Recipient, identity age.Identity, opts SelectOptions) (SelectResult, error) {
	if len(recipients) == 0 {
		return SelectResult{}, fmt.Errorf("at least one recipient is required")
	}

	pairs, err := decryptEnvPairs(encPath, identity)
	if err != nil {
		return SelectResult{}, fmt.Errorf("decrypt: %w", err)
	}

	var selected, rejected []envPair
	for _, p := range pairs {
		if matchesSelect(p.key, opts) != opts.Invert {
			selected = append(selected, p)
		} else {
			rejected = append(rejected, p)
		}
	}

	out := buildSelectBytes(selected)
	if err := crypto.EncryptFile(out, outPath, recipients); err != nil {
		return SelectResult{}, fmt.Errorf("encrypt: %w", err)
	}

	return SelectResult{Included: len(selected), Excluded: len(rejected)}, nil
}

func matchesSelect(key string, opts SelectOptions) bool {
	for _, k := range opts.Keys {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	for _, prefix := range opts.Prefixes {
		if strings.HasPrefix(strings.ToUpper(key), strings.ToUpper(prefix)) {
			return true
		}
	}
	return false
}

func buildSelectBytes(pairs []envPair) []byte {
	var sb strings.Builder
	for _, p := range pairs {
		sb.WriteString(p.key)
		sb.WriteByte('=')
		sb.WriteString(p.value)
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}
