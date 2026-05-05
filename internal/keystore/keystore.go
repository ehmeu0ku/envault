package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

const (
	defaultKeyDir  = ".envault"
	defaultKeyFile = "identity.age"
)

// KeyStore manages age identity keys on disk.
type KeyStore struct {
	dir string
}

// New returns a KeyStore rooted at the given directory.
// If dir is empty, it defaults to ~/.envault.
func New(dir string) (*KeyStore, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(home, defaultKeyDir)
	}
	return &KeyStore{dir: dir}, nil
}

// KeyPath returns the path to the identity file.
func (k *KeyStore) KeyPath() string {
	return filepath.Join(k.dir, defaultKeyFile)
}

// Exists reports whether an identity file already exists.
func (k *KeyStore) Exists() bool {
	_, err := os.Stat(k.KeyPath())
	return err == nil
}

// Generate creates a new age X25519 identity and persists it to disk.
// Returns an error if the identity already exists.
func (k *KeyStore) Generate() (*age.X25519Identity, error) {
	if k.Exists() {
		return nil, errors.New("identity already exists at " + k.KeyPath())
	}
	if err := os.MkdirAll(k.dir, 0700); err != nil {
		return nil, err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(k.KeyPath(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = f.WriteString("# age identity key\n" + id.String() + "\n")
	return id, err
}

// Load reads and parses the identity from disk.
func (k *KeyStore) Load() (*age.X25519Identity, error) {
	data, err := os.ReadFile(k.KeyPath())
	if err != nil {
		return nil, err
	}
	ids, err := age.ParseIdentities(strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errors.New("no identities found in " + k.KeyPath())
	}
	id, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, errors.New("unsupported identity type")
	}
	return id, nil
}
