package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/keystore"
	"github.com/yourorg/envault/internal/vault"
)

func init() {
	var oldPrefix, newPrefix string
	var failIfNone bool

	cmd := &cobra.Command{
		Use:   "pivot <file>",
		Short: "Rename env key prefixes inside an encrypted vault file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPivot(args[0], oldPrefix, newPrefix, failIfNone)
		},
	}

	cmd.Flags().StringVar(&oldPrefix, "old", "", "Prefix to remove from matching keys")
	cmd.Flags().StringVar(&newPrefix, "new", "", "Prefix to add in place of --old")
	cmd.Flags().BoolVar(&failIfNone, "fail-if-none", false, "Return an error if no keys matched")
	_ = cmd.MarkFlagRequired("old")
	_ = cmd.MarkFlagRequired("new")

	rootCmd.AddCommand(cmd)
}

func runPivot(file, oldPrefix, newPrefix string, failIfNone bool) error {
	home := mustHomeDir()
	ks := keystore.New(home)

	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	rec, err := ks.Recipient()
	if err != nil {
		return fmt.Errorf("load recipient: %w", err)
	}

	v := vault.New(".")
	res, err := v.Pivot(file, []interface{ String() string }{rec}, id, vault.PivotOptions{
		OldPrefix:  oldPrefix,
		NewPrefix:  newPrefix,
		FailIfNone: failIfNone,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "pivot: %d key(s) renamed, %d unchanged\n", res.Renamed, res.Unchanged)
	return nil
}
