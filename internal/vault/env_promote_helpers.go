package vault

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/subtlepseudonym/envault/internal/crypto"
	"filippo.io/age"
)

// decryptEnvPairs decrypts an age-encrypted .env file and returns
// its key-value pairs as a map.
func decryptEnvPairs(encPath string, identity age.Identity) (map[string]string, error) {
	tmpOut, err := os.CreateTemp("", "envault-promote-dec-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpOut.Name())
	tmpOut.Close()

	if err := crypto.DecryptFile(encPath, tmpOut.Name(), identity); err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	f, err := os.Open(tmpOut.Name())
	if err != nil {
		return nil, fmt.Errorf("open decrypted: %w", err)
	}
	defer f.Close()

	pairs := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		pairs[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return pairs, nil
}
