package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/vault"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Show the audit log for vault operations",
	RunE:  runAudit,
}

var auditLimit int

func init() {
	auditCmd.Flags().IntVarP(&auditLimit, "limit", "n", 20, "Maximum number of recent events to show")
}

func runAudit(cmd *cobra.Command, args []string) error {
	vaultDir := mustHomeDir()

	log, err := vault.LoadAuditLog(vaultDir)
	if err != nil {
		return fmt.Errorf("loading audit log: %w", err)
	}

	events := log.Events
	if len(events) == 0 {
		fmt.Println("No audit events recorded.")
		return nil
	}

	// Show most recent events first, up to limit.
	if auditLimit > 0 && len(events) > auditLimit {
		events = events[len(events)-auditLimit:]
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tOPERATION\tTARGET\tSTATUS\tMESSAGE")
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]
		status := "ok"
		if !ev.Success {
			status = "fail"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			ev.Timestamp.Local().Format(time.RFC3339),
			ev.Operation,
			ev.Target,
			status,
			ev.Message,
		)
	}
	return w.Flush()
}
