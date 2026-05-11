package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/vault"
)

var (
	checkIdentityFlag string
	checkKeysFlag     []string
)

func init() {
	checkCmd := &cobra.Command{
		Use:   "check <env-file>",
		Short: "Check which keys are present in an encrypted .env file",
		Args:  cobra.ExactArgs(1),
		RunE:  runCheck,
	}
	checkCmd.Flags().StringVarP(&checkIdentityFlag, "identity", "i", defaultIdentityPath(), "Path to age identity file")
	checkCmd.Flags().StringSliceVarP(&checkKeysFlag, "keys", "k", nil, "Comma-separated list of keys to check (default: all)")
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	envFile := args[0]
	v := vault.New(mustHomeDir())

	report, err := v.CheckEnv(envFile, checkIdentityFlag, checkKeysFlag)
	if err != nil {
		return fmt.Errorf("check: %w", err)
	}

	fmt.Fprintf(os.Stdout, "File: %s\n", report.File)
	fmt.Fprintf(os.Stdout, "%-30s %s\n", "KEY", "STATUS")
	fmt.Fprintf(os.Stdout, "%s\n", strings.Repeat("-", 42))

	for _, r := range report.Results {
		status := "✓ present"
		if !r.Present {
			status = "✗ missing"
		}
		fmt.Fprintf(os.Stdout, "%-30s %s\n", r.Key, status)
	}

	if len(report.Missing) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d key(s) missing: %s\n", len(report.Missing), strings.Join(report.Missing, ", "))
		os.Exit(1)
	}

	return nil
}
