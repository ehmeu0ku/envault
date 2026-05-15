package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/keystore"
	"github.com/yourorg/envault/internal/vault"
)

func init() {
	var (
		keys    []string
		prefix  string
		reveal  int
		output  string
		vaultDir string
	)

	cmd := &cobra.Command{
		Use:   "mask <file.env.age>",
		Short: "Print a masked view of an encrypted .env file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMask(args[0], vaultDir, output, keys, prefix, reveal)
		},
	}

	cmd.Flags().StringSliceVar(&keys, "key", nil, "explicit key names to mask (comma-separated)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "mask all keys with this prefix")
	cmd.Flags().IntVar(&reveal, "reveal", 0, "reveal first N characters of masked values")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write masked output to file (default: stdout)")
	cmd.Flags().StringVar(&vaultDir, "vault-dir", mustHomeDir()+"/.envault", "vault directory")

	rootCmd.AddCommand(cmd)
}

func runMask(encPath, vaultDir, output string, keys []string, prefix string, reveal int) error {
	ks, err := keystore.New(vaultDir)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	out := output
	if out == "" {
		// Write to a temp file then print, so we can stream to stdout.
		tmp, err := os.CreateTemp("", "envault-mask-*")
		if err != nil {
			return fmt.Errorf("temp file: %w", err)
		}
		tmp.Close()
		defer os.Remove(tmp.Name())
		out = tmp.Name()
	}

	opts := vault.MaskOptions{
		Keys:   keys,
		Prefix: prefix,
		Reveal: reveal,
	}

	res, err := vault.Mask(vaultDir, encPath, out, id, opts)
	if err != nil {
		return err
	}

	if output == "" {
		data, err := os.ReadFile(out)
		if err != nil {
			return err
		}
		fmt.Print(string(data))
	} else {
		fmt.Fprintf(os.Stderr, "masked %d key(s), skipped %d\n", res.Masked, res.Skipped)
	}

	summary := fmt.Sprintf("masked %d key(s)", res.Masked)
	if prefix != "" {
		summary += fmt.Sprintf(" with prefix %q", prefix)
	}
	if len(keys) > 0 {
		summary += fmt.Sprintf(" [%s]", strings.Join(keys, ","))
	}
	_ = summary
	return nil
}
