package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/yourorg/envault/internal/vault"
)

func init() {
	profileCmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage named environment profiles",
	}

	addCmd := &cobra.Command{
		Use:   "add <name> <env-file>",
		Short: "Register a named profile pointing to an env file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileAdd(args[0], args[1])
		},
	}

	removeCmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a named profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileRemove(args[0])
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all registered profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileList()
		},
	}

	profileCmd.AddCommand(addCmd, removeCmd, listCmd)
	rootCmd.AddCommand(profileCmd)
}

func runProfileAdd(name, envFile string) error {
	dir := mustHomeDir()
	if err := vault.AddProfile(dir, name, envFile); err != nil {
		return fmt.Errorf("add profile: %w", err)
	}
	fmt.Printf("Profile %q registered → %s\n", name, envFile)
	return nil
}

func runProfileRemove(name string) error {
	dir := mustHomeDir()
	if err := vault.RemoveProfile(dir, name); err != nil {
		return fmt.Errorf("remove profile: %w", err)
	}
	fmt.Printf("Profile %q removed.\n", name)
	return nil
}

func runProfileList() error {
	dir := mustHomeDir()
	idx, err := vault.LoadProfiles(dir)
	if err != nil {
		return fmt.Errorf("load profiles: %w", err)
	}
	if len(idx) == 0 {
		fmt.Println("No profiles registered.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tENV FILE\tUPDATED")
	for _, p := range idx {
		fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.EnvFile, p.UpdatedAt.Format("2006-01-02 15:04:05"))
	}
	return w.Flush()
}
