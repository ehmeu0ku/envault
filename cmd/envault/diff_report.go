package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/keystore"
	"github.com/yourorg/envault/internal/vault"
)

var diffReportFormat string

func init() {
	cmd := &cobra.Command{
		Use:   "diff-report <file-a> <file-b>",
		Short: "Show a structured diff between two sealed .env files",
		Args:  cobra.ExactArgs(2),
		RunE:  runDiffReport,
	}
	cmd.Flags().StringVarP(&diffReportFormat, "format", "f", "text", "Output format: text or json")
	rootCmd.AddCommand(cmd)
}

func runDiffReport(cmd *cobra.Command, args []string) error {
	home := mustHomeDir()
	ks := keystore.New(home)
	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	vaultDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working dir: %w", err)
	}

	var fmt_ vault.DiffReportFormat
	switch diffReportFormat {
	case "json":
		fmt_ = vault.DiffReportJSON
	default:
		fmt_ = vault.DiffReportText
	}

	return vault.DiffReport(vaultDir, args[0], args[1], identity, fmt_, os.Stdout)
}
