package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/subtlepseudonym/envault/internal/crypto"
)

// ResolveOptions controls how variable interpolation is performed.
type ResolveOptions struct {
	// FallbackToEnv allows unresolved references to fall back to the
	// current process environment.
	FallbackToEnv bool
	// FailOnMissing causes Resolve to return an error when a referenced
	// variable cannot be resolved.
	FailOnMissing bool
}

// ResolveResult holds the outcome of a Resolve call.
type ResolveResult struct {
	Pairs    []EnvPair
	Resolved int
	Missing  []string
}

// EnvPair is a simple key/value pair.
type EnvPair struct {
	Key   string
	Value string
}

// Resolve decrypts the sealed .env file at envPath and expands any
// ${VAR} or $VAR references found in values using the other decrypted
// pairs first, then optionally the host environment.
func Resolve(vaultDir, envPath string, identity age.Identity, opts ResolveOptions) (ResolveResult, error) {
	encPath := encryptedPath(envPath)
	full := filepath.Join(vaultDir, encPath)
	if _, err := os.Stat(full); err != nil {
		return ResolveResult{}, fmt.Errorf("resolve: encrypted file not found: %w", err)
	}

	tmp, err := os.CreateTemp("", "envault-resolve-*")
	if err != nil {
		return ResolveResult{}, fmt.Errorf("resolve: create temp: %w", err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	if err := crypto.DecryptFile(full, tmp.Name(), identity); err != nil {
		return ResolveResult{}, fmt.Errorf("resolve: decrypt: %w", err)
	}

	raw, err := os.ReadFile(tmp.Name())
	if err != nil {
		return ResolveResult{}, fmt.Errorf("resolve: read decrypted: %w", err)
	}

	pairs := parseResolvePairs(string(raw))
	lookup := make(map[string]string, len(pairs))
	for _, p := range pairs {
		lookup[p.Key] = p.Value
	}

	var result ResolveResult
	for _, p := range pairs {
		expanded := os.Expand(p.Value, func(key string) string {
			if v, ok := lookup[key]; ok {
				result.Resolved++
				return v
			}
			if opts.FallbackToEnv {
				if v, ok := os.LookupEnv(key); ok {
					result.Resolved++
					return v
				}
			}
			result.Missing = append(result.Missing, key)
			return ""
		})
		result.Pairs = append(result.Pairs, EnvPair{Key: p.Key, Value: expanded})
	}

	if opts.FailOnMissing && len(result.Missing) > 0 {
		return result, fmt.Errorf("resolve: unresolved references: %s", strings.Join(result.Missing, ", "))
	}

	return result, nil
}

func parseResolvePairs(content string) []EnvPair {
	var pairs []EnvPair
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
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		pairs = append(pairs, EnvPair{Key: key, Value: val})
	}
	return pairs
}
