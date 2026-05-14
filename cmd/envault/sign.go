package main

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/vault"
)

func init() {
	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign and verify encrypted vault files",
	}

	signFileCmd := &cobra.Command{
		Use:   "file <env-file.age>",
		Short: "Sign an encrypted vault file with an HMAC key",
		Args:  cobra.ExactArgs(1),
		RunE:  runSign,
	}
	signFileCmd.Flags().String("key-file", "", "Path to file containing HMAC signing key (required)")
	_ = signFileCmd.MarkFlagRequired("key-file")

	verifyCmd := &cobra.Command{
		Use:   "verify <env-file.age>",
		Short: "Verify the signature of an encrypted vault file",
		Args:  cobra.ExactArgs(1),
		RunE:  runVerifySign,
	}
	verifyCmd.Flags().String("key-file", "", "Path to file containing HMAC signing key (required)")
	_ = verifyCmd.MarkFlagRequired("key-file")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all signature records in the vault",
		RunE:  runSignList,
	}

	signCmd.AddCommand(signFileCmd, verifyCmd, listCmd)
	rootCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) error {
	encFile := args[0]
	keyFile, _ := cmd.Flags().GetString("key-file")
	vaultDir := filepath.Dir(encFile)

	key, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	if err := vault.SignFile(vaultDir, encFile, key); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "signed: %s\n", encFile)
	return nil
}

func runVerifySign(cmd *cobra.Command, args []string) error {
	encFile := args[0]
	keyFile, _ := cmd.Flags().GetString("key-file")
	vaultDir := filepath.Dir(encFile)

	key, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	if err := vault.VerifySignature(vaultDir, encFile, key); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "ok: signature valid for %s\n", encFile)
	return nil
}

func runSignList(cmd *cobra.Command, args []string) error {
	vaultDir := mustHomeDir()
	records, err := vault.LoadSignatures(vaultDir)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no signatures recorded")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tSIGNATURE\tSIGNED AT")
	for _, r := range records {
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.File, r.Signature[:12]+"...", r.SignedAt.Format(time.RFC3339))
	}
	return w.Flush()
}
