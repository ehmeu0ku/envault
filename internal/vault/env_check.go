package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckResult holds the result of an environment check for a single key.
type CheckResult struct {
	Key     string
	Present bool
	Value   string
}

// CheckReport holds the full report for an env check operation.
type CheckReport struct {
	File    string
	Results []CheckResult
	Missing []string
}

// CheckEnv decrypts the given .env.age file using the provided identity and
// checks whether the given keys are present in the decrypted content.
// It returns a CheckReport summarising the findings.
func (v *Vault) CheckEnv(envFile string, identity string, keys []string) (*CheckReport, error) {
	encPath := encryptedPath(envFile)
	if _, err := os.Stat(encPath); err != nil {
		return nil, fmt.Errorf("encrypted file not found: %s", encPath)
	}

	tmpFile, err := os.CreateTemp("", "envault-check-*.env")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	if err := v.Unseal(encPath, tmpFile.Name(), identity); err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("read decrypted file: %w", err)
	}

	pairs := parseCheckEnvFile(string(data))
	keyMap := make(map[string]string, len(pairs))
	for _, p := range pairs {
		keyMap[p[0]] = p[1]
	}

	report := &CheckReport{File: filepath.Base(envFile)}
	keySet := keys
	if len(keySet) == 0 {
		for k := range keyMap {
			keySet = append(keySet, k)
		}
	}

	for _, k := range keySet {
		val, ok := keyMap[k]
		report.Results = append(report.Results, CheckResult{Key: k, Present: ok, Value: val})
		if !ok {
			report.Missing = append(report.Missing, k)
		}
	}

	return report, nil
}

func parseCheckEnvFile(content string) [][2]string {
	var pairs [][2]string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		pairs = append(pairs, [2]string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])})
	}
	return pairs
}
