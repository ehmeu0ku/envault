package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var keyPath string

var rootCmd = &cobra.Command{
	Use:   "envault",
	Short: "envault — local secret manager for .env files",
	Long: `envault encrypts and decrypts .env files using age encryption
so they can be safely stored in version control.`,
}

func init() {
	defaultKey := filepath.Join(mustHomeDir(), ".config", "envault", "key.txt")
	rootCmd.PersistentFlags().StringVar(&keyPath, "key", defaultKey, "path to age identity file")

	rootCmd.AddCommand(sealCmd)
	rootCmd.AddCommand(unsealCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func mustHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot determine home directory:", err)
		os.Exit(1)
	}
	return home
}
