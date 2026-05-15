package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/nicholasgasior/envault/internal/keystore"
	"github.com/nicholasgasior/envault/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	cmd := &cobra.Command{
		Use:   "setdefault <file.env.age> KEY=VALUE...",
		Short: "Fill in missing keys with default values",
		Long: `Decrypt the vault file and set any keys that are not already present.
Use --overwrite to replace existing values.`,
		Args: cobra.MinimumNArgs(2),
		RunE: runSetDefault,
	}
	cmd.Flags().Bool("overwrite", false, "Replace existing values with the supplied defaults")
	rootCmd.AddCommand(cmd)
}

func runSetDefault(cmd *cobra.Command, args []string) error {
	encPath := args[0]
	overwrite, _ := cmd.Flags().GetBool("overwrite")

	defaults := make(map[string]string)
	for _, arg := range args[1:] {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid KEY=VALUE pair: %q", arg)
		}
		defaults[parts[0]] = parts[1]
	}

	homeDir := mustHomeDir()
	ks, err := keystore.New(homeDir)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	rec := id.Recipient()

	vaultDir := "."
	if d, err := os.Getwd(); err == nil {
		vaultDir = d
	}

	result, err := vault.SetDefault(vaultDir, encPath, defaults, id, rec,
		vault.SetDefaultOptions{Overwrite: overwrite})
	if err != nil {
		return err
	}

	for _, k := range result.Set {
		fmt.Fprintf(cmd.OutOrStdout(), "set   %s\n", k)
	}
	for _, k := range result.Skipped {
		fmt.Fprintf(cmd.OutOrStdout(), "skip  %s (already set)\n", k)
	}
	return nil
}
