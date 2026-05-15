package vault

import (
	"fmt"
	"strings"

	"github.com/nicholasgasior/envault/internal/crypto"
	age "filippo.io/age"
)

// FlattenOptions controls how key names are transformed during flattening.
type FlattenOptions struct {
	Prefix    string // optional prefix to prepend to all keys
	Separator string // separator between prefix and key (default: "_")
	Uppercase bool   // normalize keys to uppercase
	DryRun    bool   // if true, print result without writing
}

// FlattenResult holds the outcome of a Flatten operation.
type FlattenResult struct {
	Transformed int
	Skipped     int
}

// Flatten decrypts an encrypted .env file, applies key name transformations
// (prefix, case normalization), and re-encrypts the result in place.
func (v *Vault) Flatten(envPath string, identity age.Identity, recipient age.Recipient, opts FlattenOptions) (FlattenResult, error) {
	encPath := encryptedPath(envPath)

	pairs, err := decryptEnvPairs(encPath, identity)
	if err != nil {
		return FlattenResult{}, fmt.Errorf("flatten: decrypt: %w", err)
	}

	sep := opts.Separator
	if sep == "" {
		sep = "_"
	}

	var result FlattenResult
	var sb strings.Builder

	for _, p := range pairs {
		key := p[0]
		val := p[1]

		if opts.Prefix != "" {
			key = opts.Prefix + sep + key
			result.Transformed++
		} else {
			result.Skipped++
		}

		if opts.Uppercase {
			key = strings.ToUpper(key)
			result.Transformed++
		}

		sb.WriteString(key)
		sb.WriteByte('=')
		sb.WriteString(val)
		sb.WriteByte('\n')
	}

	if opts.DryRun {
		fmt.Print(sb.String())
		return result, nil
	}

	if err := crypto.EncryptFile(strings.NewReader(sb.String()), encPath, recipient); err != nil {
		return FlattenResult{}, fmt.Errorf("flatten: encrypt: %w", err)
	}

	return result, nil
}
