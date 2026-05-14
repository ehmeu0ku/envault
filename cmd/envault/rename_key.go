package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/keystore"
	"github.com/yourorg/envault/internal/vault"
)

func init() {
	var failIfMissing bool

	cmd := &cobra.Command{
		Use:   "rename-key <file.env.age> <old-key> <new-key>",
		Short: "Rename a key inside a sealed vault file",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRenameKey(args[0], args[1], args[2], failIfMissing)
		},
	}
	cmd.Flags().BoolVar(&failIfMissing, "fail-if-missing", false,
		"Return a non-zero exit code when the old key does not exist")

	rootCmd.AddCommand(cmd)
}

func runRenameKey(encPath, oldKey, newKey string, failIfMissing bool) error {
	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("open keystore: %w", err)
	}
	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	rec := id.Recipient()

	res, err := vault.RenameKey(
		encPath, id, []interface{ /* age.Recipient */ }{rec},
		oldKey, newKey,
		vault.RenameKeyOptions{FailIfMissing: failIfMissing},
	)
	if err != nil {
		return err
	}

	if res.Renamed {
		fmt.Fprintf(os.Stdout, "renamed %q → %q in %s\n", oldKey, newKey, encPath)
	} else {
		fmt.Fprintf(os.Stdout, "key %q not found in %s — no changes made\n", oldKey, encPath)
	}
	return nil
}
