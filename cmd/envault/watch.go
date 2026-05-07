package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/keystore"
	"github.com/yourorg/envault/internal/vault"
)

var watchInterval time.Duration

func init() {
	watchCmd := &cobra.Command{
		Use:   "watch <file.env>",
		Short: "Watch a .env file and auto-seal on changes",
		Args:  cobra.ExactArgs(1),
		RunE:  runWatch,
	}
	watchCmd.Flags().DurationVarP(&watchInterval, "interval", "i", 2*time.Second, "polling interval")
	rootCmd.AddCommand(watchCmd)
}

func runWatch(cmd *cobra.Command, args []string) error {
	plainPath := args[0]

	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	id, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	rec := id.Recipient()

	fmt.Fprintf(os.Stderr, "Watching %s (interval: %s) — press Ctrl-C to stop\n", plainPath, watchInterval)

	done := make(chan struct{})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go vault.Watch(
		plainPath,
		watchInterval,
		[]interface{ String() string }{rec},
		[]interface{}{id},
		func(r vault.WatchResult) {
			if r.Err != nil {
				fmt.Fprintf(os.Stderr, "[watch] error sealing %s: %v\n", r.Path, r.Err)
				return
			}
			if r.Changed {
				fmt.Fprintf(os.Stderr, "[watch] sealed %s\n", r.Path)
			}
		},
		done,
	)

	<-sigs
	close(done)
	fmt.Fprintln(os.Stderr, "\nWatch stopped.")
	return nil
}
