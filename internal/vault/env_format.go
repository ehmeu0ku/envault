package vault

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/cipherlock/envault/internal/crypto"
)

// FormatOptions controls how the vault file is formatted on write.
type FormatOptions struct {
	SortKeys    bool
	StripBlanks bool
	NormalizeQuotes bool
}

// FormatResult holds a summary of changes made during formatting.
type FormatResult struct {
	KeysSorted   int
	BlanksRemoved int
	QuotesNormalized int
}

// Format decrypts a sealed env file, applies formatting rules, then re-encrypts it.
func Format(vaultDir, name string, identity age.Identity, recipients []age.Recipient, opts FormatOptions) (FormatResult, error) {
	v := New(vaultDir)
	encPath := v.encryptedPath(name)

	if _, err := os.Stat(encPath); err != nil {
		return FormatResult{}, fmt.Errorf("encrypted file not found: %w", err)
	}

	pairs, err := crypto.DecryptFile(encPath, identity)
	if err != nil {
		return FormatResult{}, fmt.Errorf("decrypt: %w", err)
	}

	lines := strings.Split(strings.TrimRight(string(pairs), "\n"), "\n")
	result := FormatResult{}

	var kept []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if opts.StripBlanks && trimmed == "" {
			result.BlanksRemoved++
			continue
		}
		if opts.NormalizeQuotes && strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(trimmed, "=", 2)
			val := parts[1]
			if (strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`)) ||
				(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
				unquoted := val[1 : len(val)-1]
				newLine := parts[0] + "=" + unquoted
				if newLine != trimmed {
					result.QuotesNormalized++
					trimmed = newLine
				}
			}
		}
		kept = append(kept, trimmed)
	}

	if opts.SortKeys {
		var comments, envLines []string
		for _, l := range kept {
			if strings.HasPrefix(l, "#") || l == "" {
				comments = append(comments, l)
			} else {
				envLines = append(envLines, l)
			}
		}
		sort.Strings(envLines)
		result.KeysSorted = len(envLines)
		kept = append(comments, envLines...)
	}

	formatted := []byte(strings.Join(kept, "\n") + "\n")
	if err := crypto.EncryptFile(encPath, formatted, recipients); err != nil {
		return FormatResult{}, fmt.Errorf("re-encrypt: %w", err)
	}

	return result, nil
}
