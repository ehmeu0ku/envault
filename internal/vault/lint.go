package vault

import (
	"fmt"
	"strings"
)

// LintIssue represents a single linting problem found in a .env file.
type LintIssue struct {
	Line    int
	Message string
}

func (i LintIssue) String() string {
	return fmt.Sprintf("line %d: %s", i.Line, i.Message)
}

// LintResult holds all issues found for a given file.
type LintResult struct {
	File   string
	Issues []LintIssue
}

func (r LintResult) OK() bool {
	return len(r.Issues) == 0
}

// Lint decrypts the encrypted .env file at envPath and checks for common
// issues: duplicate keys, empty keys, keys with whitespace, and missing values.
func (v *Vault) Lint(envPath string) (LintResult, error) {
	enc := encryptedPath(envPath)
	pairs, err := v.decryptToPairs(enc)
	if err != nil {
		return LintResult{}, fmt.Errorf("lint: decrypt %s: %w", enc, err)
	}

	result := LintResult{File: envPath}
	seen := make(map[string]int)

	for i, p := range pairs {
		lineNo := i + 1
		key := p[0]
		val := p[1]

		if key == "" {
			result.Issues = append(result.Issues, LintIssue{Line: lineNo, Message: "empty key"})
			continue
		}
		if strings.ContainsAny(key, " \t") {
			result.Issues = append(result.Issues, LintIssue{Line: lineNo, Message: fmt.Sprintf("key %q contains whitespace", key)})
		}
		if val == "" {
			result.Issues = append(result.Issues, LintIssue{Line: lineNo, Message: fmt.Sprintf("key %q has empty value", key)})
		}
		if prev, dup := seen[key]; dup {
			result.Issues = append(result.Issues, LintIssue{Line: lineNo, Message: fmt.Sprintf("duplicate key %q (first seen on line %d)", key, prev)})
		} else {
			seen[key] = lineNo
		}
	}

	return result, nil
}

// decryptToPairs is a small helper that decrypts an age file and returns
// key/value pairs using the shared parseEnvFile helper from diff.go.
func (v *Vault) decryptToPairs(encPath string) ([][2]string, error) {
	plaintext, err := decryptToString(v.identity, encPath)
	if err != nil {
		return nil, err
	}
	return parseEnvFile(plaintext), nil
}
