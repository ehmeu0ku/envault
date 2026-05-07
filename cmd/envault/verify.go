package main

import (
	"fmt"
	"os"

	"github.com/nicholasgasior/envault/internal/keystore"
	"github.com/nicholasgasior/envault/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	verifyCmd := &cobra.Command{
		Use:   "verify [file]",
		Short: "Verify integrity of encrypted .env file(s)",
		Long: `Verify that encrypted .env.age files can be decrypted with the current
identity, confirming their integrity without writing any output.

If no file is specified, all encrypted files in the vault are verified.`,
		RunE: runVerify,
	}
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	homeDir := mustHomeDir()
	ks := keystore.New(homeDir)

	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("failed to load identity: %w", err)
	}

	v := vault.New(".")

	if len(args) == 0 {
		// Verify all encrypted files
		results, err := v.VerifyAll(id)
		if err != nil {
			return fmt.Errorf("verify all failed: %w", err)
		}
		if len(results) == 0 {
			fmt.Println("No encrypted files found.")
			return nil
		}
		allOK := true
		for _, r := range results {
			status := "✓"
			if !r.OK {
				status = "✗"
				allOK = false
			}
			fmt.Printf("%s  %s  %s\n", status, r.Path, r.Message)
		}
		if !allOK {
			os.Exit(1)
		}
		return nil
	}

	// Verify a specific file
	result, err := v.Verify(args[0], id)
	if err != nil {
		return fmt.Errorf("verify failed: %w", err)
	}
	if result.OK {
		fmt.Printf("✓  %s  %s\n", result.Path, result.Message)
	} else {
		fmt.Printf("✗  %s  %s\n", result.Path, result.Message)
		os.Exit(1)
	}
	return nil
}
