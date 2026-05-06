package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/keystore"
	"github.com/yourorg/envault/internal/vault"
)

var editCmd = &cobra.Command{
	Use:   "edit [file]",
	Short: "Decrypt a vault file, open it in an editor, then re-encrypt",
	Long: `Decrypts the specified .env.age file to a temporary location,
opens it in your $EDITOR (or vi by default), and re-encrypts the
result back to the vault once you save and quit.

The plaintext file is never written to the project directory;
it lives only in a temporary file that is securely removed after use.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runEdit,
}

func init() {
	rootCmd.AddCommand(editCmd)
}

func runEdit(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Resolve the key store from the default location.
	homedir := mustHomeDir()
	ks, err := keystore.New(homedir)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	// Load the age identity used for decryption / re-encryption.
	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Determine the editor to use.
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = "vi"
	}

	// Open the vault rooted at the current working directory.
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}

	v, err := vault.New(cwd, identity)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}

	// Wrap the edit operation with audit logging.
	err = vault.WithAudit(homedir, "edit", target, func() error {
		return v.Edit(target, editor)
	})
	if err != nil {
		return fmt.Errorf("edit %s: %w", target, err)
	}

	fmt.Printf("✓ %s re-encrypted successfully\n", target)
	return nil
}
