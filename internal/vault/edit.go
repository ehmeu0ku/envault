package vault

import (
	"fmt"
	"os"
	"os/exec"

	"filippo.io/age"
)

// Edit decrypts the vault file to a temp file, opens it in the user's editor,
// then re-encrypts the modified content back to the vault.
func (v *Vault) Edit(name string, identity *age.X25519Identity, editor string) error {
	encPath := encryptedPath(name)
	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		return fmt.Errorf("vault file not found: %s", encPath)
	}

	// Create a temp file to hold the decrypted content.
	tmp, err := os.CreateTemp("", "envault-edit-*.env")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()

	// Ensure the temp file is removed when we're done.
	defer os.Remove(tmpPath)

	// Restrict permissions on the temp file before writing secrets.
	if err := os.Chmod(tmpPath, 0600); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}

	// Decrypt existing vault content into the temp file.
	if err := v.Unseal(name, identity); err != nil {
		return fmt.Errorf("unseal for edit: %w", err)
	}
	// Unseal writes to name; move it to tmpPath.
	if err := os.Rename(name, tmpPath); err != nil {
		return fmt.Errorf("move decrypted file: %w", err)
	}

	// Record modification time before opening the editor.
	beforeStat, err := os.Stat(tmpPath)
	if err != nil {
		return fmt.Errorf("stat temp file: %w", err)
	}

	// Open the editor.
	cmd := exec.Command(editor, tmpPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor exited with error: %w", err)
	}

	// Check whether the file was actually modified.
	afterStat, err := os.Stat(tmpPath)
	if err != nil {
		return fmt.Errorf("stat temp file after edit: %w", err)
	}
	if afterStat.ModTime().Equal(beforeStat.ModTime()) {
		fmt.Println("No changes made, vault unchanged.")
		return nil
	}

	// Move the edited file to the plain name so Seal can pick it up.
	if err := os.Rename(tmpPath, name); err != nil {
		return fmt.Errorf("restore edited file: %w", err)
	}

	// Re-encrypt the edited file.
	recipient := identity.Recipient()
	if err := v.Seal(name, recipient); err != nil {
		return fmt.Errorf("seal after edit: %w", err)
	}

	fmt.Printf("Vault %s updated successfully.\n", encPath)
	return nil
}
