package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"envault/internal/vault"
)

func init() {
	hookCmd := &cobra.Command{
		Use:   "hook",
		Short: "Manage lifecycle hooks for seal/unseal events",
	}

	installCmd := &cobra.Command{
		Use:   "install <event> <script-file>",
		Short: "Install a hook script for a lifecycle event (pre-seal, post-seal, pre-unseal, post-unseal)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			event := vault.HookEvent(args[0])
			content, err := os.ReadFile(args[1])
			if err != nil {
				return fmt.Errorf("read script: %w", err)
			}
			vaultDir, _ := cmd.Flags().GetString("vault-dir")
			if err := vault.InstallHook(vaultDir, event, string(content)); err != nil {
				return err
			}
			fmt.Printf("Hook %q installed.\n", event)
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List installed hooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultDir, _ := cmd.Flags().GetString("vault-dir")
			hooks, err := vault.ListHooks(vaultDir)
			if err != nil {
				return err
			}
			if len(hooks) == 0 {
				fmt.Println("No hooks installed.")
				return nil
			}
			for _, h := range hooks {
				fmt.Println(string(h))
			}
			return nil
		},
	}

	installCmd.Flags().String("vault-dir", mustHomeDir()+"/.envault", "vault directory")
	listCmd.Flags().String("vault-dir", mustHomeDir()+"/.envault", "vault directory")

	hookCmd.AddCommand(installCmd, listCmd)
	rootCmd.AddCommand(hookCmd)
}
