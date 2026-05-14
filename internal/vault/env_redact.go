package vault

import (
	"fmt"
	"regexp"
	"strings"

	"filippo.io/age"

	"github.com/rgst-io/envault/internal/crypto"
)

// RedactOptions controls how secrets are redacted in output.
type RedactOptions struct {
	// ShowKeys controls whether key names are shown (values are always masked).
	ShowKeys bool
	// MaskChar is the character used to mask values. Defaults to "*".
	MaskChar string
	// RevealKeys is a list of keys whose values should NOT be redacted.
	RevealKeys []string
}

// RedactResult holds the redacted output lines.
type RedactResult struct {
	Lines []string
}

// Redact decrypts an encrypted env file and returns a redacted view,
// masking all secret values unless explicitly allowed.
func Redact(encPath string, identity age.Identity, opts RedactOptions) (*RedactResult, error) {
	if !strings.HasSuffix(encPath, ".age") {
		return nil, fmt.Errorf("redact: expected .age file, got %q", encPath)
	}

	pairs, err := decryptEnvPairs(encPath, identity)
	if err != nil {
		return nil, fmt.Errorf("redact: decrypt failed: %w", err)
	}

	mask := opts.MaskChar
	if mask == "" {
		mask = "*"
	}

	allowSet := make(map[string]bool, len(opts.RevealKeys))
	for _, k := range opts.RevealKeys {
		allowSet[k] = true
	}

	result := &RedactResult{}
	for _, p := range pairs {
		key := p[0]
		val := p[1]

		if !allowSet[key] {
			val = maskValue(val, mask)
		}

		if opts.ShowKeys {
			result.Lines = append(result.Lines, fmt.Sprintf("%s=%s", key, val))
		} else {
			result.Lines = append(result.Lines, fmt.Sprintf("%s=%s", redactKey(key), val))
		}
	}

	return result, nil
}

// maskValue replaces all non-whitespace characters with the mask character.
func maskValue(val, mask string) string {
	if val == "" {
		return ""
	}
	return strings.Repeat(mask, 8)
}

var keyRedactRe = regexp.MustCompile(`[a-zA-Z0-9]`)

// redactKey partially obscures a key name, keeping first and last char.
func redactKey(key string) string {
	if len(key) <= 2 {
		return key
	}
	return string(key[0]) + strings.Repeat("*", len(key)-2) + string(key[len(key)-1])
}

// RedactFile writes a redacted view of the vault file to a writer.
func RedactFile(encPath string, identity age.Identity, opts RedactOptions) (string, error) {
	_ = crypto.DecryptFile // ensure import used
	_ = keyRedactRe
	res, err := Redact(encPath, identity, opts)
	if err != nil {
		return "", err
	}
	return strings.Join(res.Lines, "\n"), nil
}
