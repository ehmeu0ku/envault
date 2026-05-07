package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/keystore"
	"github.com/yourorg/envault/internal/vault"
)

var importOverwrite bool

func init() {
	importCmd := &cobra.Command{
		Use:   "import <env-file>",
		Short: "Import key=value pairs from a plain .env file into the encrypted vault",
		Args:  cobra.ExactArgs(1),
		RunE:  runImport,
	}
	importCmd.Flags().BoolVarP(&importOverwrite, "overwrite", "f", false,
		"overwrite existing keys in the vault")
	rootCmd.AddCommand(importCmd)
}

func runImport(cmd *cobra.Command, args []string) error {
	envFile := args[0]

	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	v, err := vault.New(".")
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}

	v.SetIdentity(id)

	result, err := vault.WithAudit(v, "import", envFile, func() error {
		res, ierr := v.Import(envFile, id.Recipient(), importOverwrite)
		if ierr != nil {
			return ierr
		}
		fmt.Fprintf(os.Stdout, "imported %d key(s), skipped %d key(s) → %s\n",
			res.Imported, res.Skipped, res.File)
		return nil
	})
	_ = result
	return err
}
