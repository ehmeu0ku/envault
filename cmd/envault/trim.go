package main

import (
	"fmt"
	"os"

	"github.com/nicholasgasior/envault/internal/keystore"
	"github.com/nicholasgasior/envault/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	trimCmd := &cobra.Command{
		Use:   "trim <file.env.age>",
		Short: "Normalise whitespace, quotes, and key casing inside a vault file",
		Args:  cobra.ExactArgs(1),
		RunE:  runTrim,
	}

	trimCmd.Flags().Bool("trim-space", true, "Strip leading/trailing whitespace from values")
	trimCmd.Flags().Bool("remove-quotes", false, "Remove surrounding quotes from values")
	trimCmd.Flags().Bool("normalize-keys", false, "Uppercase all key names")

	rootCmd.AddCommand(trimCmd)
}

func runTrim(cmd *cobra.Command, args []string) error {
	encPath := args[0]

	trimSpace, _ := cmd.Flags().GetBool("trim-space")
	removeQuotes, _ := cmd.Flags().GetBool("remove-quotes")
	normalizeKeys, _ := cmd.Flags().GetBool("normalize-keys")

	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	recipient := identity.Recipient()

	opts := vault.TrimOptions{
		TrimSpace:     trimSpace,
		RemoveQuotes:  removeQuotes,
		NormalizeKeys: normalizeKeys,
	}

	result, err := vault.Trim(encPath, identity, recipient, opts)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "trim: %s\n", encPath)
	if opts.TrimSpace {
		fmt.Fprintf(os.Stdout, "  values trimmed:  %d\n", result.Trimmed)
	}
	if opts.RemoveQuotes {
		fmt.Fprintf(os.Stdout, "  quotes removed:  %d\n", result.Unquoted)
	}
	if opts.NormalizeKeys {
		fmt.Fprintf(os.Stdout, "  keys uppercased: %d\n", result.Renamed)
	}

	return nil
}
