package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/nicholasgasior/envault/internal/keystore"
	"github.com/nicholasgasior/envault/internal/vault"
)

func init() {
	cmd := &cobra.Command{
		Use:   "compare <file-a.env.age> <file-b.env.age>",
		Short: "Compare two encrypted vault files",
		Args:  cobra.ExactArgs(2),
		RunE:  runCompare,
	}
	rootCmd.AddCommand(cmd)
}

func runCompare(cmd *cobra.Command, args []string) error {
	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	v, err := vault.New(".")
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}

	result, err := v.Compare(args[0], args[1], identity)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Summary: %s\n", result.Summary())

	if len(result.OnlyInA) > 0 {
		fmt.Fprintf(os.Stdout, "\nOnly in %s:\n", args[0])
		for _, k := range result.OnlyInA {
			fmt.Fprintf(os.Stdout, "  - %s\n", k)
		}
	}
	if len(result.OnlyInB) > 0 {
		fmt.Fprintf(os.Stdout, "\nOnly in %s:\n", args[1])
		for _, k := range result.OnlyInB {
			fmt.Fprintf(os.Stdout, "  + %s\n", k)
		}
	}
	if len(result.Different) > 0 {
		fmt.Fprintf(os.Stdout, "\nModified keys:\n")
		for _, k := range result.Different {
			fmt.Fprintf(os.Stdout, "  ~ %s\n", k)
		}
	}
	if len(result.Identical) > 0 {
		fmt.Fprintf(os.Stdout, "\nUnchanged keys:\n")
		for _, k := range result.Identical {
			fmt.Fprintf(os.Stdout, "  = %s\n", k)
		}
	}
	return nil
}
