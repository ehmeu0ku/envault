package vault

import (
	"fmt"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// PivotOptions controls how Pivot rewrites keys.
type PivotOptions struct {
	// OldPrefix is the prefix to remove from matching keys.
	OldPrefix string
	// NewPrefix is the prefix to add in its place.
	NewPrefix string
	// FailIfNone returns an error when no keys matched the old prefix.
	FailIfNone bool
}

// PivotResult holds a summary of the pivot operation.
type PivotResult struct {
	Renamed int
	Unchanged int
}

// Pivot decrypts the .age file at src, replaces OldPrefix with NewPrefix on
// every matching key, then re-encrypts the result in place.
func (v *Vault) Pivot(src string, recipients []age.Recipient, identity age.Identity, opts PivotOptions) (PivotResult, error) {
	encPath := encryptedPath(src)
	if !filepath.IsAbs(encPath) {
		encPath = filepath.Join(v.dir, encPath)
	}

	pairs, err := decryptEnvPairs(encPath, identity)
	if err != nil {
		return PivotResult{}, fmt.Errorf("pivot: decrypt %s: %w", encPath, err)
	}

	var result PivotResult
	var sb strings.Builder

	for _, p := range pairs {
		key, val := p[0], p[1]
		if opts.OldPrefix != "" && strings.HasPrefix(key, opts.OldPrefix) {
			key = opts.NewPrefix + strings.TrimPrefix(key, opts.OldPrefix)
			result.Renamed++
		} else {
			result.Unchanged++
		}
		sb.WriteString(key)
		sb.WriteByte('=')
		sb.WriteString(val)
		sb.WriteByte('\n')
	}

	if opts.FailIfNone && result.Renamed == 0 {
		return result, fmt.Errorf("pivot: no keys matched prefix %q", opts.OldPrefix)
	}

	plain := []byte(sb.String())
	if err := encryptToFile(encPath, plain, recipients); err != nil {
		return result, fmt.Errorf("pivot: re-encrypt %s: %w", encPath, err)
	}

	return result, nil
}

// encryptToFile is a thin helper that encrypts plaintext bytes to a file path.
func encryptToFile(dst string, plain []byte, recipients []age.Recipient) error {
	tmp := dst + ".tmp"
	if err := EncryptFile(plain, tmp, recipients); err != nil {
		return err
	}
	return renameFile(tmp, dst)
}
