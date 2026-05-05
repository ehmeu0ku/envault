package vault

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// DiffResult holds the comparison between a plaintext .env and its encrypted counterpart.
type DiffResult struct {
	OnlyInPlain     []string
	OnlyInEncrypted []string
	Modified        []string
	Unchanged       []string
}

// HasChanges returns true if there are any differences between the two files.
func (d *DiffResult) HasChanges() bool {
	return len(d.OnlyInPlain) > 0 || len(d.OnlyInEncrypted) > 0 || len(d.Modified) > 0
}

// Diff decrypts the sealed version of envPath and compares keys/values with the
// current plaintext file. It returns a DiffResult describing what changed.
func (v *Vault) Diff(envPath string) (*DiffResult, error) {
	encPath := encryptedPath(envPath)
	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("no encrypted file found for %s", envPath)
	}

	// Decrypt to a temp file.
	tmp, err := os.CreateTemp("", "envault-diff-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	if err := v.Unseal(encPath); err != nil {
		return nil, fmt.Errorf("unseal for diff: %w", err)
	}
	// Unseal writes to envPath; move that to tmpPath so we can compare.
	if err := os.Rename(envPath, tmpPath); err != nil {
		return nil, fmt.Errorf("rename decrypted file: %w", err)
	}

	plain, err := parseEnvFile(envPath + ".orig")
	if err != nil {
		// Fall back: read the original plaintext if it still exists.
		plain, err = parseEnvFile(envPath)
		if err != nil {
			plain = map[string]string{}
		}
	}

	decrypted, err := parseEnvFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("parse decrypted env: %w", err)
	}

	return computeDiff(plain, decrypted), nil
}

func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result, scanner.Err()
}

func computeDiff(plain, encrypted map[string]string) *DiffResult {
	result := &DiffResult{}
	for k, v := range plain {
		ev, ok := encrypted[k]
		if !ok {
			result.OnlyInPlain = append(result.OnlyInPlain, k)
		} else if v != ev {
			result.Modified = append(result.Modified, k)
		} else {
			result.Unchanged = append(result.Unchanged, k)
		}
	}
	for k := range encrypted {
		if _, ok := plain[k]; !ok {
			result.OnlyInEncrypted = append(result.OnlyInEncrypted, k)
		}
	}
	return result
}
