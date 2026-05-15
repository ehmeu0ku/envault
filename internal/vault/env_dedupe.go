package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/nicholasgasior/envault/internal/crypto"
	age "filippo.io/age"
)

// DedupeResult holds the outcome of a deduplication operation.
type DedupeResult struct {
	Removed []string
	Kept    map[string]string
}

// Dedupe decrypts the sealed env file at encPath, removes duplicate keys
// (keeping the last occurrence), re-encrypts, and writes back to encPath.
func Dedupe(encPath string, identity age.Identity, recipient age.Recipient) (DedupeResult, error) {
	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		return DedupeResult{}, fmt.Errorf("encrypted file not found: %s", encPath)
	}

	plain, err := crypto.DecryptFile(encPath, identity)
	if err != nil {
		return DedupeResult{}, fmt.Errorf("decrypt: %w", err)
	}

	pairs, removed := dedupeEnvBytes(plain)

	var sb strings.Builder
	for _, kv := range pairs {
		sb.WriteString(kv[0])
		sb.WriteByte('=')
		sb.WriteString(kv[1])
		sb.WriteByte('\n')
	}

	if err := crypto.EncryptFile([]byte(sb.String()), encPath, recipient); err != nil {
		return DedupeResult{}, fmt.Errorf("encrypt: %w", err)
	}

	kept := make(map[string]string, len(pairs))
	for _, kv := range pairs {
		kept[kv[0]] = kv[1]
	}

	return DedupeResult{Removed: removed, Kept: kept}, nil
}

// dedupeEnvBytes parses raw env bytes, returns ordered unique pairs (last wins)
// and a list of keys that had duplicates removed.
func dedupeEnvBytes(data []byte) ([][2]string, []string) {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")

	seen := make(map[string]int)   // key -> index in ordered
	ordered := make([][2]string, 0, len(lines))
	duplicates := map[string]bool{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := line[:idx]
		val := line[idx+1:]

		if prev, exists := seen[key]; exists {
			// overwrite previous entry in-place
			ordered[prev] = [2]string{key, val}
			duplicates[key] = true
		} else {
			seen[key] = len(ordered)
			ordered = append(ordered, [2]string{key, val})
		}
	}

	removed := make([]string, 0, len(duplicates))
	for k := range duplicates {
		removed = append(removed, k)
	}
	return ordered, removed
}
