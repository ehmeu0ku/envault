package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	age "filippo.io/age"

	"github.com/user/envault/internal/keystore"
	"github.com/user/envault/internal/vault"
)

var shareRecipients []string
var shareOutput string

func init() {
	shareCmd := &cobra.Command{
		Use:   "share <env-file>",
		Short: "Re-encrypt a sealed vault file for additional recipients",
		Args:  cobra.ExactArgs(1),
		RunE:  runShare,
	}
	shareCmd.Flags().StringArrayVarP(&shareRecipients, "recipient", "r", nil,
		"age public key of a recipient (may be repeated)")
	shareCmd.Flags().StringVarP(&shareOutput, "output", "o", "",
		"destination path for the shared encrypted file (required)")
	_ = shareCmd.MarkFlagRequired("recipient")
	_ = shareCmd.MarkFlagRequired("output")
	rootCmd.AddCommand(shareCmd)
}

func runShare(cmd *cobra.Command, args []string) error {
	envFile := args[0]

	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	var recipients []age.Recipient
	for _, pub := range shareRecipients {
		recipient, err := age.ParseX25519Recipient(pub)
		if err != nil {
			return fmt.Errorf("invalid recipient %q: %w", pub, err)
		}
		recipients = append(recipients, recipient)
	}

	v, err := vault.New(".", identity)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}

	if err := v.Share(envFile, recipients, shareOutput); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "shared %s → %s (%d recipient(s))\n",
		envFile, shareOutput, len(recipients))
	return nil
}
