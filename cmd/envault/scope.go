package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nicholasgasior/envault/internal/keystore"
	"github.com/nicholasgasior/envault/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	var prefix string
	var dest string
	var overwrite bool

	cmd := &cobra.Command{
		Use:   "scope <env-file>",
		Short: "Re-encrypt an env file with all keys prefixed by a scope string",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScope(args[0], prefix, dest, overwrite)
		},
	}

	cmd.Flags().StringVarP(&prefix, "prefix", "p", "", "Scope prefix to add to every key (required)")
	cmd.Flags().StringVarP(&dest, "dest", "d", "", "Destination env file path (defaults to <src>.<prefix>)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite destination if it already exists")
	_ = cmd.MarkFlagRequired("prefix")

	rootCmd.AddCommand(cmd)
}

func runScope(src, prefix, dest string, overwrite bool) error {
	home := mustHomeDir()
	ks := keystore.New(filepath.Join(home, ".envault", "key.txt"))
	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	if dest == "" {
		dest = src + "." + prefix
	}

	vaultDir := filepath.Dir(src)

	rec := id.Recipient()
	opts := vault.ScopeOptions{
		Prefix:    prefix,
		Overwrite: overwrite,
	}

	result, err := vault.Scope(vaultDir, src, dest, []interface{ String() string }{rec}, id, opts)
	if err != nil {
		return err
	}

	absDest, _ := filepath.Abs(dest + ".age")
	fmt.Fprintf(os.Stdout, "Scoped %d key(s) with prefix %q → %s\n", result.Added, prefix, absDest)
	return nil
}
