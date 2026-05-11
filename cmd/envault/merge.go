package main

import (
	"fmt"
	"os"

	"github.com/nicholasgasior/envault/internal/keystore"
	"github.com/nicholasgasior/envault/internal/vault"
	"github.com/spf13/cobra"
)

var (
	mergeOverwrite bool
)

func init() {
	mergeCmd := &cobra.Command{
		Use:   "merge <src> <dst>",
		Short: "Merge keys from one encrypted env file into another",
		Long: `Decrypt both src and dst .env.age files, merge key-value pairs from src
into dst, then re-encrypt dst. By default, conflicting keys in dst are kept.
Use --overwrite to replace them with values from src.`,
		Args: cobra.ExactArgs(2),
		RunE: runMerge,
	}
	mergeCmd.Flags().BoolVar(&mergeOverwrite, "overwrite", false, "overwrite conflicting keys in destination")
	rootCmd.AddCommand(mergeCmd)
}

func runMerge(cmd *cobra.Command, args []string) error {
	src, dst := args[0], args[1]

	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	rec, err := ks.Recipient()
	if err != nil {
		return fmt.Errorf("load recipient: %w", err)
	}

	v := vault.New(".")

	strategy := vault.MergeStrategySkip
	if mergeOverwrite {
		strategy = vault.MergeStrategyOverwrite
	}

	result, err := v.Merge(src, dst, id, rec, strategy)
	if err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	if len(result.Added) > 0 {
		fmt.Fprintf(w, "Added (%d):\n", len(result.Added))
		for _, k := range result.Added {
			fmt.Fprintf(w, "  + %s\n", k)
		}
	}
	if len(result.Overwritten) > 0 {
		fmt.Fprintf(w, "Overwritten (%d):\n", len(result.Overwritten))
		for _, k := range result.Overwritten {
			fmt.Fprintf(w, "  ~ %s\n", k)
		}
	}
	if len(result.Skipped) > 0 {
		fmt.Fprintf(w, "Skipped (%d):\n", len(result.Skipped))
		for _, k := range result.Skipped {
			fmt.Fprintf(w, "  = %s\n", k)
		}
	}

	fmt.Fprintln(w, "Merge complete.")
	_ = os.Stderr // suppress unused import
	return nil
}
