package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/envault/envault/internal/keystore"
	"github.com/envault/envault/internal/vault"
)

func init() {
	var keys []string
	var prefix string

	cmd := &cobra.Command{
		Use:   "strip <file.env.age>",
		Short: "Remove keys from a sealed vault file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStrip(args[0], keys, prefix)
		},
	}

	cmd.Flags().StringArrayVarP(&keys, "key", "k", nil, "Key name to remove (repeatable)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "Remove all keys with this prefix")

	rootCmd.AddCommand(cmd)
}

func runStrip(encPath string, keys []string, prefix string) error {
	if len(keys) == 0 && prefix == "" {
		return fmt.Errorf("strip: provide at least one --key or --prefix")
	}

	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	recipient := identity.Recipient()

	opts := vault.StripOptions{
		Keys:   keys,
		Prefix: prefix,
	}

	res, err := vault.Strip("", encPath, identity, []interface{ String() string }{recipient}, opts)
	if err != nil {
		return err
	}

	if len(res.Removed) == 0 {
		fmt.Fprintln(os.Stdout, "strip: no matching keys found")
	} else {
		fmt.Fprintf(os.Stdout, "stripped %d key(s): %s\n", len(res.Removed), strings.Join(res.Removed, ", "))
	}
	fmt.Fprintf(os.Stdout, "retained %d key(s)\n", res.Retained)
	return nil
}
