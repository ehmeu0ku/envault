package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/keystore"
	"github.com/yourorg/envault/internal/vault"
)

func init() {
	rootCmd.AddCommand(lintCmd)
}

var lintCmd = &cobra.Command{
	Use:   "lint [file]",
	Short: "Check an encrypted .env file for common issues",
	Args:  cobra.ExactArgs(1),
	RunE:  runLint,
}

func runLint(cmd *cobra.Command, args []string) error {
	envPath := args[0]

	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	v := vault.New(".", id)
	res, err := v.Lint(envPath)
	if err != nil {
		return err
	}

	if res.OK() {
		fmt.Fprintf(cmd.OutOrStdout(), "✓ %s — no issues found\n", envPath)
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "✗ %s — %d issue(s):\n", envPath, len(res.Issues))
	for _, iss := range res.Issues {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", iss)
	}

	// Exit with a non-zero code so CI pipelines can detect problems.
	os.Exit(1)
	return nil
}
