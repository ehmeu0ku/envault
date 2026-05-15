package vault

import (
	"fmt"
	"strings"

	"filippo.io/age"
)

// MaskOptions controls which keys are masked and how.
type MaskOptions struct {
	// Keys is an explicit list of keys to mask. If empty, all keys are masked.
	Keys []string
	// Prefix masks any key whose name starts with this prefix.
	Prefix string
	// Reveal shows the first N characters of each value (0 = full mask).
	Reveal int
}

// MaskResult holds the outcome of a mask operation.
type MaskResult struct {
	Masked  int
	Skipped int
}

// Mask decrypts the vault file at encPath using identity, applies masking
// rules defined by opts, and writes the masked plaintext to outPath.
func Mask(vaultDir, encPath, outPath string, identity *age.X25519Identity, opts MaskOptions) (MaskResult, error) {
	pairs, err := decryptEnvPairs(vaultDir, encPath, identity)
	if err != nil {
		return MaskResult{}, fmt.Errorf("mask: decrypt: %w", err)
	}

	keySet := make(map[string]bool, len(opts.Keys))
	for _, k := range opts.Keys {
		keySet[k] = true
	}

	var sb strings.Builder
	var result MaskResult

	for _, p := range pairs {
		if shouldMaskKey(p[0], keySet, opts.Prefix) {
			sb.WriteString(p[0])
			sb.WriteByte('=')
			sb.WriteString(applyMask(p[1], opts.Reveal))
			sb.WriteByte('\n')
			result.Masked++
		} else {
			sb.WriteString(p[0])
			sb.WriteByte('=')
			sb.WriteString(p[1])
			sb.WriteByte('\n')
			result.Skipped++
		}
	}

	if err := writeOutputFile(outPath, []byte(sb.String())); err != nil {
		return MaskResult{}, fmt.Errorf("mask: write output: %w", err)
	}

	return result, nil
}

func shouldMaskKey(key string, keySet map[string]bool, prefix string) bool {
	if len(keySet) == 0 && prefix == "" {
		return true
	}
	if keySet[key] {
		return true
	}
	if prefix != "" && strings.HasPrefix(key, prefix) {
		return true
	}
	return false
}

func applyMask(value string, reveal int) string {
	if len(value) == 0 {
		return "****"
	}
	if reveal <= 0 || reveal >= len(value) {
		return strings.Repeat("*", len(value))
	}
	return value[:reveal] + strings.Repeat("*", len(value)-reveal)
}

// writeOutputFile writes data to path, creating it if necessary.
func writeOutputFile(path string, data []byte) error {
	if path == "" {
		return nil
	}
	return writeFileAtomic(path, data)
}
