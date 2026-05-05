package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/user/envault/internal/crypto"
	"github.com/user/envault/internal/keystore"
)

const encryptedSuffix = ".age"

// Vault manages encryption and decryption of .env files.
type Vault struct {
	ks *keystore.KeyStore
}

// New creates a new Vault using the provided KeyStore.
func New(ks *keystore.KeyStore) *Vault {
	return &Vault{ks: ks}
}

// Seal encrypts the given .env file, writing a .age file alongside it.
// Returns the path of the encrypted file.
func (v *Vault) Seal(envPath string) (string, error) {
	if _, err := os.Stat(envPath); err != nil {
		return "", fmt.Errorf("seal: source file not found: %w", err)
	}

	identity, err := v.ks.Load()
	if err != nil {
		return "", fmt.Errorf("seal: load identity: %w", err)
	}

	recipient, err := identity.Recipient()
	if err != nil {
		return "", fmt.Errorf("seal: derive recipient: %w", err)
	}

	outPath := encryptedPath(envPath)
	if err := crypto.EncryptFile(envPath, outPath, recipient); err != nil {
		return "", fmt.Errorf("seal: encrypt: %w", err)
	}

	return outPath, nil
}

// Unseal decrypts the given .age file, writing the plaintext .env file.
// Returns the path of the decrypted file.
func (v *Vault) Unseal(agePath string) (string, error) {
	if !strings.HasSuffix(agePath, encryptedSuffix) {
		return "", fmt.Errorf("unseal: expected %s suffix, got %q", encryptedSuffix, agePath)
	}

	if _, err := os.Stat(agePath); err != nil {
		return "", fmt.Errorf("unseal: source file not found: %w", err)
	}

	identity, err := v.ks.Load()
	if err != nil {
		return "", fmt.Errorf("unseal: load identity: %w", err)
	}

	outPath := strings.TrimSuffix(agePath, encryptedSuffix)
	if err := crypto.DecryptFile(agePath, outPath, identity); err != nil {
		return "", fmt.Errorf("unseal: decrypt: %w", err)
	}

	return outPath, nil
}

// encryptedPath returns the .age output path for a given source path.
func encryptedPath(src string) string {
	dir := filepath.Dir(src)
	base := filepath.Base(src)
	return filepath.Join(dir, base+encryptedSuffix)
}
