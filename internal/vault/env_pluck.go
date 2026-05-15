package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/yourusername/envault/internal/crypto"
)

// PluckOptions configures the Pluck operation.
type PluckOptions struct {
	VaultDir  string
	Identity  string
	Keys      []string
	OutputFmt string // "dotenv", "export", "json"
}

// PluckResult holds the extracted key-value pairs.
type PluckResult struct {
	Pairs map[string]string
	Missing []string
}

// Pluck decrypts a sealed .env file and returns only the requested keys.
func Pluck(envFile string, opts PluckOptions) (*PluckResult, error) {
	encPath := encryptedPath(envFile)
	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("encrypted file not found: %s", encPath)
	}

	if len(opts.Keys) == 0 {
		return nil, fmt.Errorf("at least one key must be specified")
	}

	plaintext, err := crypto.DecryptFile(encPath, opts.Identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	allPairs := parsePluckEnvFile(string(plaintext))

	result := &PluckResult{
		Pairs: make(map[string]string),
	}

	wanted := make(map[string]bool, len(opts.Keys))
	for _, k := range opts.Keys {
		wanted[k] = true
	}

	for _, pair := range allPairs {
		if wanted[pair[0]] {
			result.Pairs[pair[0]] = pair[1]
			delete(wanted, pair[0])
		}
	}

	for k := range wanted {
		result.Missing = append(result.Missing, k)
	}

	return result, nil
}

// parsePluckEnvFile parses KEY=VALUE lines, skipping comments and blanks.
func parsePluckEnvFile(content string) [][2]string {
	var pairs [][2]string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"`)
		if key != "" {
			pairs = append(pairs, [2]string{key, val})
		}
	}
	return pairs
}
