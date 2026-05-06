package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/keystore"
	"github.com/yourorg/envault/internal/vault"
)

func init() {
	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Manage vault snapshots",
	}

	takeCmd := &cobra.Command{
		Use:   "take [file]",
		Short: "Take a snapshot of the current sealed vault",
		Args:  cobra.ExactArgs(1),
		RunE:  runSnapshotTake,
	}

	listCmd := &cobra.Command{
		Use:   "list [file]",
		Short: "List available snapshots for a vault file",
		Args:  cobra.ExactArgs(1),
		RunE:  runSnapshotList,
	}

	restoreCmd := &cobra.Command{
		Use:   "restore [file] [snapshot-id]",
		Short: "Restore a vault from a snapshot",
		Args:  cobra.ExactArgs(2),
		RunE:  runSnapshotRestore,
	}

	snapshotCmd.AddCommand(takeCmd, listCmd, restoreCmd)
	rootCmd.AddCommand(snapshotCmd)
}

func runSnapshotTake(cmd *cobra.Command, args []string) error {
	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return err
	}
	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	v := vault.New(".", args[0])
	snapID, err := v.TakeSnapshot(id.Recipient())
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "snapshot created: %s\n", snapID)
	return nil
}

func runSnapshotList(cmd *cobra.Command, args []string) error {
	v := vault.New(".", args[0])
	snaps, err := v.ListSnapshots()
	if err != nil {
		return err
	}
	if len(snaps) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no snapshots found")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTAKEN AT")
	for _, s := range snaps {
		fmt.Fprintf(w, "%s\t%s\n", s.ID, s.TakenAt.Format(time.RFC3339))
	}
	return w.Flush()
}

func runSnapshotRestore(cmd *cobra.Command, args []string) error {
	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return err
	}
	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	v := vault.New(".", args[0])
	if err := v.RestoreSnapshot(args[1], id); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "restored %s from snapshot %s\n", args[0], args[1])
	return nil
}

func snapshotOutputOrStdout(cmd *cobra.Command) *os.File {
	return os.Stdout
}
