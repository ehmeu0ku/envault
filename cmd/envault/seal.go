package main

import (
	"fmt"
	"os"

	"github.com/user/envault/internal/keystore"
	"github.com/user/envault/internal/vault"
	"github.com/spf13/cobra"
)

var sealCmd = &cobra.Command{
	Use:   "seal [file]",
	Short: "Encrypt a .env file into an .age file",
	Args:  cobra.ExactArgs(1),
	RunE:  runSeal,
}

var unsealCmd = &cobra.Command{
	Use:   "unseal [file]",
	Short: "Decrypt an .age file back into a .env file",
	Args:  cobra.ExactArgs(1),
	RunE:  runUnseal,
}

func runSeal(cmd *cobra.Command, args []string) error {
	ks := keystore.New(keyPath)
	v := vault.New(ks)

	out, err := v.Seal(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return err
	}

	fmt.Printf("sealed: %s\n", out)
	return nil
}

func runUnseal(cmd *cobra.Command, args []string) error {
	ks := keystore.New(keyPath)
	v := vault.New(ks)

	out, err := v.Unseal(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return err
	}

	fmt.Printf("unsealed: %s\n", out)
	return nil
}
