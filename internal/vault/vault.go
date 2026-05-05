package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/user/envault/internal/crypto"
)

const ageSuffix = ".age"

// Vault manages encryption and decryption of .env files in a directory.
type Vault struct {
	dir      string
	identity *age.X25519Identity
	crypto   *crypto.Crypto
}

// New creates a Vault rooted at dir using the provided identity.
func New(dir string, identity *age.X25519Identity) *Vault {
	return &Vault{
		dir:      dir,
		identity: identity,
		crypto:   crypto.New(),
	}
}

// Seal encrypts name (e.g. ".env") inside the vault directory.
func (v *Vault) Seal(name string) error {
	src := filepath.Join(v.dir, name)
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return fmt.Errorf("seal: source file not found: %s", src)
	}
	dst := encryptedPath(v.dir, name)
	return v.crypto.EncryptFile(src, dst, v.identity.Recipient())
}

// Unseal decrypts the sealed version of name back to its original path.
func (v *Vault) Unseal(name string) error {
	if !strings.HasSuffix(name, ageSuffix) {
		return fmt.Errorf("unseal: expected %s suffix, got: %s", ageSuffix, name)
	}
	src := filepath.Join(v.dir, name)
	dst := filepath.Join(v.dir, strings.TrimSuffix(name, ageSuffix))
	return v.crypto.DecryptFile(src, dst, v.identity)
}

// UnsealTo decrypts the sealed version of envName to an explicit output path.
func (v *Vault) UnsealTo(envName, outPath string) error {
	encPath := encryptedPath(v.dir, envName)
	return v.crypto.DecryptFile(encPath, outPath, v.identity)
}

// encryptedPath returns the expected path of the encrypted file for name.
func encryptedPath(dir, name string) string {
	return filepath.Join(dir, name+ageSuffix)
}
