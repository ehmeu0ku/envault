package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nicholasgasior/envault/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	archiveCmd := &cobra.Command{
		Use:   "archive",
		Short: "Archive and extract encrypted vault files",
	}

	packCmd := &cobra.Command{
		Use:   "pack [dest.zip]",
		Short: "Pack all .age files in the vault into a zip archive",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runArchivePack,
	}

	unpackCmd := &cobra.Command{
		Use:   "unpack <archive.zip> [dest-dir]",
		Short: "Unpack a vault archive into a directory",
		Args:  cobra.RangeArgs(1, 2),
		RunE:  runArchiveUnpack,
	}

	archiveCmd.AddCommand(packCmd, unpackCmd)
	rootCmd.AddCommand(archiveCmd)
}

func runArchivePack(cmd *cobra.Command, args []string) error {
	vaultDir := mustHomeDir()

	var destPath string
	if len(args) == 1 {
		destPath = args[0]
	} else {
		stamp := time.Now().UTC().Format("20060102-150405")
		destPath = fmt.Sprintf("envault-%s.zip", stamp)
	}

	n, err := vault.Archive(vaultDir, destPath)
	if err != nil {
		return fmt.Errorf("pack: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Packed %d encrypted file(s) → %s\n", n, destPath)
	return nil
}

func runArchiveUnpack(cmd *cobra.Command, args []string) error {
	archivePath := args[0]

	var destDir string
	if len(args) == 2 {
		destDir = args[1]
	} else {
		base := filepath.Base(archivePath)
		for _, ext := range []string{".zip", ".tar.gz"} {
			if len(base) > len(ext) {
				base = base[:len(base)-len(ext)]
			}
		}
		destDir = base
	}

	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		return fmt.Errorf("unpack: archive not found: %s", archivePath)
	}

	result, err := vault.Extract(archivePath, destDir)
	if err != nil {
		return fmt.Errorf("unpack: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Extracted %d file(s) → %s\n", result.Extracted, destDir)
	if !result.Manifest.CreatedAt.IsZero() {
		fmt.Fprintf(cmd.OutOrStdout(), "Archive created at: %s\n", result.Manifest.CreatedAt.Format(time.RFC3339))
	}
	return nil
}
