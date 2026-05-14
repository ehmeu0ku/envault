package main

import (
	"fmt"
	"os"

	"github.com/cipherlock/envault/internal/keystore"
	"github.com/cipherlock/envault/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	formatCmd := &cobra.Command{
		Use:   "format [file]",
		Short: "Format a sealed .env file in-place",
		Args:  cobra.ExactArgs(1),
		RunE:  runFormat,
	}
	formatCmd.Flags().Bool("sort", false, "Sort keys alphabetically")
	formatCmd.Flags().Bool("strip-blanks", false, "Remove blank lines")
	formatCmd.Flags().Bool("normalize-quotes", false, "Strip surrounding quotes from values")
	rootCmd.AddCommand(formatCmd)
}

func runFormat(cmd *cobra.Command, args []string) error {
	name := args[0]
	vaultDir := mustHomeDir()

	sortKeys, _ := cmd.Flags().GetBool("sort")
	stripBlanks, _ := cmd.Flags().GetBool("strip-blanks")
	normalizeQuotes, _ := cmd.Flags().GetBool("normalize-quotes")

	if !sortKeys && !stripBlanks && !normalizeQuotes {
		return fmt.Errorf("specify at least one formatting option (--sort, --strip-blanks, --normalize-quotes)")
	}

	ks, err := keystore.New(vaultDir)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	recipient := identity.Recipient()

	opts := vault.FormatOptions{
		SortKeys:        sortKeys,
		StripBlanks:     stripBlanks,
		NormalizeQuotes: normalizeQuotes,
	}

	res, err := vault.Format(vaultDir, name, identity, []age.Recipient{recipient}, opts)
	if err != nil {
		return fmt.Errorf("format: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Formatted %s\n", name)
	if res.KeysSorted > 0 {
		fmt.Fprintf(os.Stdout, "  sorted %d keys\n", res.KeysSorted)
	}
	if res.BlanksRemoved > 0 {
		fmt.Fprintf(os.Stdout, "  removed %d blank lines\n", res.BlanksRemoved)
	}
	if res.QuotesNormalized > 0 {
		fmt.Fprintf(os.Stdout, "  normalized quotes on %d values\n", res.QuotesNormalized)
	}
	return nil
}
