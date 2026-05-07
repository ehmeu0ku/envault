package vault

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
)

// ImportResult holds the outcome of an import operation.
type ImportResult struct {
	Imported int
	Skipped  int
	File     string
}

// Import reads key=value pairs from a plain-text source file and merges them
// into an existing encrypted vault file. Existing keys are overwritten only
// when overwrite is true; otherwise they are skipped.
func (v *Vault) Import(envFile string, recipient age.Recipient, overwrite bool) (*ImportResult, error) {
	incoming, err := readEnvPairs(envFile)
	if err != nil {
		return nil, fmt.Errorf("import: read source: %w", err)
	}

	encPath := encryptedPath(envFile)

	existing := map[string]string{}
	if _, err := os.Stat(encPath); err == nil {
		pairs, err := v.decryptToPairs(encPath)
		if err != nil {
			return nil, fmt.Errorf("import: decrypt existing: %w", err)
		}
		for _, p := range pairs {
			existing[p[0]] = p[1]
		}
	}

	result := &ImportResult{File: encPath}
	for _, p := range incoming {
		if _, exists := existing[p[0]]; exists && !overwrite {
			result.Skipped++
			continue
		}
		existing[p[0]] = p[1]
		result.Imported++
	}

	if err := v.encryptMapToFile(existing, encPath, recipient); err != nil {
		return nil, fmt.Errorf("import: encrypt merged: %w", err)
	}

	return result, nil
}

// readEnvPairs parses a .env file into ordered key/value pairs.
func readEnvPairs(path string) ([][2]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pairs [][2]string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"'`)
		pairs = append(pairs, [2]string{key, val})
	}
	return pairs, scanner.Err()
}
