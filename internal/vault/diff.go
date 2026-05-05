package vault

import (
	"bufio"
	"fmt"
	"strings"
)

// DiffResult holds the result of comparing plain vs encrypted env files.
type DiffResult struct {
	Modified    []string
	OnlyInPlain []string
	OnlyInEnc   []string
}

// HasChanges returns true if any differences were found.
func (d DiffResult) HasChanges() bool {
	return len(d.Modified) > 0 || len(d.OnlyInPlain) > 0 || len(d.OnlyInEnc) > 0
}

// Diff compares the plain .env file with its encrypted counterpart.
func (v *Vault) Diff(name string) (DiffResult, error) {
	plainPath := fmt.Sprintf("%s/%s", v.dir, name)
	encPath := encryptedPath(v.dir, name)

	plainData, err := readFileOrEmpty(plainPath)
	if err != nil {
		return DiffResult{}, fmt.Errorf("read plain file: %w", err)
	}

	tmpFile, err := decryptToTemp(v, encPath)
	if err != nil {
		return DiffResult{}, fmt.Errorf("decrypt for diff: %w", err)
	}
	defer removeTemp(tmpFile)

	encData, err := readFileOrEmpty(tmpFile)
	if err != nil {
		return DiffResult{}, fmt.Errorf("read decrypted file: %w", err)
	}

	plainPairs, err := parseEnvFile(plainData)
	if err != nil {
		return DiffResult{}, fmt.Errorf("parse plain: %w", err)
	}
	encPairs, err := parseEnvFile(encData)
	if err != nil {
		return DiffResult{}, fmt.Errorf("parse encrypted: %w", err)
	}

	return computeDiff(plainPairs, encPairs), nil
}

func computeDiff(plain, enc []envPair) DiffResult {
	var result DiffResult
	plainMap := pairsToMap(plain)
	encMap := pairsToMap(enc)

	for k, pv := range plainMap {
		if ev, ok := encMap[k]; !ok {
			result.OnlyInPlain = append(result.OnlyInPlain, k)
		} else if pv != ev {
			result.Modified = append(result.Modified, k)
		}
	}
	for k := range encMap {
		if _, ok := plainMap[k]; !ok {
			result.OnlyInEnc = append(result.OnlyInEnc, k)
		}
	}
	return result
}

func parseEnvFile(content string) ([]envPair, error) {
	var pairs []envPair
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		pairs = append(pairs, envPair{
			Key:   strings.TrimSpace(parts[0]),
			Value: strings.TrimSpace(parts[1]),
		})
	}
	return pairs, scanner.Err()
}

func pairsToMap(pairs []envPair) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		m[p.Key] = p.Value
	}
	return m
}
