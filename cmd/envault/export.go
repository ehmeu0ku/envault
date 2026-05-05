package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/user/envault/internal/keystore"
	"github.com/user/envault/internal/vault"
)

var (
	exportFormat string
	exportOutput string
)

func init() {
	exportCmd := &cobra.Command{
		Use:   "export <file>",
		Short: "Export decrypted secrets in various formats",
		Long: `Decrypt an encrypted .env file and print its contents.

Supported formats:
  dotenv  - KEY=VALUE pairs (default)
  export  - shell export statements
  json    - JSON object`,
		Args: cobra.ExactArgs(1),
		RunE: runExport,
	}

	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "dotenv",
		"output format: dotenv, export, json")
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "",
		"write output to file instead of stdout")

	rootCmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) error {
	home := mustHomeDir()
	ks, err := keystore.New(home)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	v, err := vault.New(".", identity)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}

	fmt := vault.ExportFormat(exportFormat)

	if exportOutput != "" {
		if err := v.ExportFile(args[0], fmt, exportOutput); err != nil {
			return fmt.Errorf("export: %w", err)
		}
		cmd.Printf("Exported to %s\n", exportOutput)
		return nil
	}

	out, err := v.Export(args[0], fmt)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}

	os.Stdout.WriteString(out)
	return nil
}
