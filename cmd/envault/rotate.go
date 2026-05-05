package main

import (
	"fmt"
	"os"

	"github.com/user/envault/internal/keystore"
	"github.com/user/envault/internal/vault"
	"github.com/spf13/cobra"
)

var rotateCmd = &cobra.Command{
	Use:   "rotate [file]",
	Short: "Re-encrypt a sealed file with a new key",
	Long: `Generate a new age identity and re-encrypt the specified .env.age file.
If no file is given, all sealed files in the vault are rotated.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRotate,
}

var rotateAllFlag bool

func init() {
	rotateCmd.Flags().BoolVar(&rotateAllFlag, "all", false, "rotate all sealed files")
}

func runRotate(cmd *cobra.Command, args []string) error {
	home := mustHomeDir()
	ks, err := keystore.New(home)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Generate a new identity for rotation
	newIdentity, err := ks.Generate()
	if err != nil {
		return fmt.Errorf("generate new identity: %w", err)
	}

	v := vault.New(".", identity)

	if rotateAllFlag || len(args) == 0 {
		rotated, err := v.RotateAll(newIdentity.Recipient())
		if err != nil {
			return fmt.Errorf("rotate all: %w", err)
		}
		for _, name := range rotated {
			fmt.Fprintf(os.Stdout, "rotated: %s\n", name)
		}
		fmt.Fprintf(os.Stdout, "rotated %d file(s) with new key\n", len(rotated))
		return nil
	}

	name := args[0]
	if err := v.Rotate(name, newIdentity.Recipient()); err != nil {
		return fmt.Errorf("rotate %s: %w", name, err)
	}
	fmt.Fprintf(os.Stdout, "rotated: %s\n", name)
	return nil
}
