package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/subtlepseudonym/envault/internal/keystore"
	"github.com/subtlepseudonym/envault/internal/vault"
)

func init() {
	resolveCmd := &cobra.Command{
		Use:   "resolve <env-file>",
		Short: "Decrypt and resolve variable references in a sealed .env file",
		Args:  cobra.ExactArgs(1),
		RunE:  runResolve,
	}
	resolveCmd.Flags().BoolP("fail-missing", "f", false, "exit non-zero if any reference cannot be resolved")
	resolveCmd.Flags().BoolP("fallback-env", "e", false, "fall back to host environment for unresolved references")
	resolveCmd.Flags().StringP("format", "o", "dotenv", "output format: dotenv|export|json")
	rootCmd.AddCommand(resolveCmd)
}

func runResolve(cmd *cobra.Command, args []string) error {
	envFile := args[0]
	failMissing, _ := cmd.Flags().GetBool("fail-missing")
	fallbackEnv, _ := cmd.Flags().GetBool("fallback-env")
	format, _ := cmd.Flags().GetString("format")

	homeDir := mustHomeDir()
	ks, err := keystore.New(homeDir)
	if err != nil {
		return fmt.Errorf("open keystore: %w", err)
	}
	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	opts := vault.ResolveOptions{
		FallbackToEnv: fallbackEnv,
		FailOnMissing: failMissing,
	}
	res, err := vault.Resolve(".", envFile, id, opts)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	if len(res.Missing) > 0 && !failMissing {
		fmt.Fprintf(os.Stderr, "warning: unresolved references: %s\n", strings.Join(res.Missing, ", "))
	}

	switch format {
	case "export":
		for _, p := range res.Pairs {
			fmt.Fprintf(os.Stdout, "export %s=%q\n", p.Key, p.Value)
		}
	case "json":
		fmt.Fprintln(os.Stdout, "{")
		for i, p := range res.Pairs {
			comma := ","
			if i == len(res.Pairs)-1 {
				comma = ""
			}
			fmt.Fprintf(os.Stdout, "  %q: %q%s\n", p.Key, p.Value, comma)
		}
		fmt.Fprintln(os.Stdout, "}")
	default: // dotenv
		for _, p := range res.Pairs {
			fmt.Fprintf(os.Stdout, "%s=%q\n", p.Key, p.Value)
		}
	}

	fmt.Fprintf(os.Stderr, "resolved %d reference(s)\n", res.Resolved)
	return nil
}
