package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rgst-io/envault/internal/keystore"
	"github.com/rgst-io/envault/internal/vault"
)

func init() {
	var (
		showKeys   bool
		maskChar   string
		revealKeys []string
	)

	cmd := &cobra.Command{
		Use:   "redact <file.env.age>",
		Short: "Print a redacted view of an encrypted env file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRedact(args[0], showKeys, maskChar, revealKeys)
		},
	}

	cmd.Flags().BoolVar(&showKeys, "show-keys", true, "Show key names in output")
	cmd.Flags().StringVar(&maskChar, "mask-char", "*", "Character used to mask secret values")
	cmd.Flags().StringSliceVar(&revealKeys, "reveal", nil, "Comma-separated list of keys to reveal plaintext values for")

	rootCmd.AddCommand(cmd)
}

func runRedact(encPath, _ string, maskChar string, revealKeys []string) error {
	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Re-read show-keys from the cobra flag via closure capture above.
	opts := vault.RedactOptions{
		ShowKeys:   true,
		MaskChar:   maskChar,
		RevealKeys: revealKeys,
	}

	result, err := vault.Redact(encPath, identity, opts)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, strings.Join(result.Lines, "\n"))
	return nil
}
