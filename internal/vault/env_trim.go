package vault

import (
	"fmt"
	"strings"

	"github.com/nicholasgasior/envault/internal/crypto"
	"filippo.io/age"
)

// TrimOptions controls which trimming operations are applied.
type TrimOptions struct {
	// TrimSpace removes leading/trailing whitespace from values.
	TrimSpace bool
	// RemoveQuotes strips surrounding single or double quotes from values.
	RemoveQuotes bool
	// NormalizeKeys uppercases all key names.
	NormalizeKeys bool
}

// TrimResult summarises what was changed.
type TrimResult struct {
	Trimmed  int
	Unquoted int
	Renamed  int
}

// Trim decrypts the vault file at encPath, applies the requested normalisation
// operations to every key/value pair, then re-encrypts the result in place.
func Trim(encPath string, identity age.Identity, recipient age.Recipient, opts TrimOptions) (TrimResult, error) {
	pairs, err := decryptEnvPairs(encPath, identity)
	if err != nil {
		return TrimResult{}, fmt.Errorf("trim: decrypt: %w", err)
	}

	var result TrimResult
	var out []string

	for _, pair := range pairs {
		key, value, found := strings.Cut(pair, "=")
		if !found {
			out = append(out, pair)
			continue
		}

		newValue := value
		newKey := key

		if opts.TrimSpace {
			trimmed := strings.TrimSpace(newValue)
			if trimmed != newValue {
				result.Trimmed++
			}
			newValue = trimmed
		}

		if opts.RemoveQuotes {
			unquoted := stripQuotes(newValue)
			if unquoted != newValue {
				result.Unquoted++
			}
			newValue = unquoted
		}

		if opts.NormalizeKeys {
			upper := strings.ToUpper(newKey)
			if upper != newKey {
				result.Renamed++
			}
			newKey = upper
		}

		out = append(out, newKey+"="+newValue)
	}

	plaintext := []byte(strings.Join(out, "\n") + "\n")
	if err := crypto.EncryptFile(encPath, plaintext, recipient); err != nil {
		return TrimResult{}, fmt.Errorf("trim: encrypt: %w", err)
	}

	return result, nil
}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
