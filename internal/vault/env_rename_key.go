package vault

import (
	"fmt"
	"strings"

	"filippo.io/age"
)

// RenameKeyOptions controls behaviour of RenameKey.
type RenameKeyOptions struct {
	// FailIfMissing causes RenameKey to return an error when OldKey is not found.
	FailIfMissing bool
}

// RenameKeyResult summarises what RenameKey did.
type RenameKeyResult struct {
	Renamed bool
	OldKey  string
	NewKey  string
}

// RenameKey decrypts the sealed env file at encPath, renames oldKey to
// newKey inside the plaintext, then re-encrypts in place.
func RenameKey(
	encPath string,
	identity age.Identity,
	recipients []age.Recipient,
	oldKey, newKey string,
	opts RenameKeyOptions,
) (RenameKeyResult, error) {
	pairs, err := decryptEnvPairs(encPath, identity)
	if err != nil {
		return RenameKeyResult{}, fmt.Errorf("rename-key: decrypt %s: %w", encPath, err)
	}

	found := false
	for i, p := range pairs {
		if p[0] == oldKey {
			pairs[i][0] = newKey
			found = true
			break
		}
	}

	if !found {
		if opts.FailIfMissing {
			return RenameKeyResult{}, fmt.Errorf("rename-key: key %q not found in %s", oldKey, encPath)
		}
		return RenameKeyResult{Renamed: false, OldKey: oldKey, NewKey: newKey}, nil
	}

	plaintext := buildEnvBytes(pairs)
	if err := reEncrypt(encPath, plaintext, recipients); err != nil {
		return RenameKeyResult{}, fmt.Errorf("rename-key: re-encrypt %s: %w", encPath, err)
	}

	return RenameKeyResult{Renamed: true, OldKey: oldKey, NewKey: newKey}, nil
}

// buildEnvBytes serialises key=value pairs back to .env bytes.
func buildEnvBytes(pairs [][2]string) []byte {
	var sb strings.Builder
	for _, p := range pairs {
		sb.WriteString(p[0])
		sb.WriteByte('=')
		sb.WriteString(p[1])
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}
