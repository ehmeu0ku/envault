package vault

import (
	"fmt"
	"strings"

	"filippo.io/age"
)

// SearchResult holds a match found during a vault search.
type SearchResult struct {
	File  string
	Key   string
	Value string
}

// Search decrypts all .env.age files in the vault directory and returns
// entries whose key or value contains the given query string (case-insensitive).
func (v *Vault) Search(identity age.Identity, query string) ([]SearchResult, error) {
	entries, err := v.List()
	if err != nil {
		return nil, fmt.Errorf("search: list vault: %w", err)
	}

	q := strings.ToLower(query)
	var results []SearchResult

	for _, entry := range entries {
		pairs, err := v.decryptToPairs(entry.EncryptedPath, identity)
		if err != nil {
			// Skip files we cannot decrypt rather than aborting the whole search.
			continue
		}
		for _, p := range pairs {
			if strings.Contains(strings.ToLower(p.Key), q) ||
				strings.Contains(strings.ToLower(p.Value), q) {
				results = append(results, SearchResult{
					File:  entry.EncryptedPath,
					Key:   p.Key,
					Value: p.Value,
				})
			}
		}
	}

	return results, nil
}

// decryptToPairs decrypts an .env.age file and returns its key/value pairs.
func (v *Vault) decryptToPairs(encPath string, identity age.Identity) ([]envPair, error) {
	tmp, err := os.CreateTemp("", "envault-search-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	if err := crypto.DecryptFile(encPath, tmp.Name(), identity); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, err
	}

	return parseEnvFile(string(data)), nil
}
