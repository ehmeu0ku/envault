package crypto

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// EncryptFile encrypts the plaintext content of a .env file using the provided
// age recipient public key and writes the armored ciphertext to destPath.
func EncryptFile(srcPath, destPath, recipientKey string) error {
	recipient, err := age.ParseX25519Recipient(recipientKey)
	if err != nil {
		return fmt.Errorf("invalid recipient key: %w", err)
	}

	plaintext, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("reading source file: %w", err)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("creating destination file: %w", err)
	}
	defer out.Close()

	armorWriter := armor.NewWriter(out)
	w, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		return fmt.Errorf("initialising encryption: %w", err)
	}

	if _, err := io.Copy(w, bytes.NewReader(plaintext)); err != nil {
		return fmt.Errorf("encrypting data: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finalising encryption: %w", err)
	}
	return armorWriter.Close()
}

// DecryptFile decrypts an armored age-encrypted file using the provided
// X25519 identity (private key) and writes the plaintext to destPath.
func DecryptFile(srcPath, destPath, identityKey string) error {
	identity, err := age.ParseX25519Identity(identityKey)
	if err != nil {
		return fmt.Errorf("invalid identity key: %w", err)
	}

	ciphertext, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("reading encrypted file: %w", err)
	}

	armorReader := armor.NewReader(bytes.NewReader(ciphertext))
	r, err := age.Decrypt(armorReader, identity)
	if err != nil {
		return fmt.Errorf("decrypting data: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading decrypted stream: %w", err)
	}

	if err := os.WriteFile(destPath, plaintext, 0600); err != nil {
		return fmt.Errorf("writing decrypted file: %w", err)
	}
	return nil
}

// GenerateKey generates a new X25519 key pair and returns the identity (private
// key) string and recipient (public key) string respectively.
func GenerateKey() (identity, recipient string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", fmt.Errorf("generating key pair: %w", err)
	}
	return id.String(), id.Recipient().String(), nil
}
