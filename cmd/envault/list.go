package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"envault/internal/vault"
)

var listCmd = &cli.Command{
	Name:  "list",
	Usage: "list sealed vault entries in a directory",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "dir",
			Aliases: []string{"d"},
			Value:   ".",
			Usage:   "directory to search for .age files",
		},
	},
	Action: runList,
}

func runList(c *cli.Context) error {
	keyPath := c.String("key")
	if keyPath == "" {
		keyPath = defaultKeyPath()
	}

	v, err := vault.New(keyPath)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	dir := c.String("dir")
	entries, err := v.List(dir)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}

	if len(entries) == 0 {
		fmt.Fprintln(os.Stdout, "no sealed entries found in", dir)
		return nil
	}

	fmt.Fprintf(os.Stdout, "%-30s %s\n", "FILE", "STATUS")
	fmt.Fprintf(os.Stdout, "%-30s %s\n", "----", "------")
	for _, e := range entries {
		fmt.Fprintf(os.Stdout, "%-30s %s\n", e.Name, e.Status())
	}
	return nil
}
