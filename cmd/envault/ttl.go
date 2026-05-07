package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"envault/internal/vault"
)

func init() {
	ttlCmd := &cobra.Command{
		Use:   "ttl",
		Short: "Manage time-to-live expiry on sealed vault files",
	}

	setCmd := &cobra.Command{
		Use:   "set <file> <duration>",
		Short: "Set a TTL on a sealed vault file (e.g. 24h, 7d)",
		Args:  cobra.ExactArgs(2),
		RunE:  runTTLSet,
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List TTL entries for the current vault directory",
		Args:  cobra.NoArgs,
		RunE:  runTTLList,
	}

	purgeCmd := &cobra.Command{
		Use:   "purge",
		Short: "Remove all expired vault files",
		Args:  cobra.NoArgs,
		RunE:  runTTLPurge,
	}

	ttlCmd.AddCommand(setCmd, listCmd, purgeCmd)
	rootCmd.AddCommand(ttlCmd)
}

func runTTLSet(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	d, err := time.ParseDuration(args[1])
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", args[1], err)
	}
	vaultDir := filepath.Dir(filePath)
	if err := vault.SetTTL(vaultDir, filePath, d); err != nil {
		return fmt.Errorf("set ttl: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "TTL set: %s expires in %s\n", filePath, d)
	return nil
}

func runTTLList(cmd *cobra.Command, args []string) error {
	vaultDir, err := os.Getwd()
	if err != nil {
		return err
	}
	idx, err := vault.LoadTTLIndex(vaultDir)
	if err != nil {
		return fmt.Errorf("load ttl index: %w", err)
	}
	if len(idx) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No TTL entries found.")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tEXPIRES AT\tSTATUS")
	for _, entry := range idx {
		status := "active"
		if time.Now().After(entry.ExpiresAt) {
			status = "EXPIRED"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", entry.Path, entry.ExpiresAt.Format(time.RFC3339), status)
	}
	return w.Flush()
}

func runTTLPurge(cmd *cobra.Command, args []string) error {
	vaultDir, err := os.Getwd()
	if err != nil {
		return err
	}
	purged, err := vault.PurgeExpired(vaultDir)
	if err != nil {
		return fmt.Errorf("purge: %w", err)
	}
	if len(purged) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No expired files to purge.")
		return nil
	}
	for _, p := range purged {
		fmt.Fprintf(cmd.OutOrStdout(), "purged: %s\n", p)
	}
	return nil
}
