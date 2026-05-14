package main

import (
	"fmt"
	"os"

	"github.com/subtlepseudonym/envault/internal/keystore"
	"github.com/subtlepseudonym/envault/internal/vault"
	"github.com/urfave/cli/v2"
)

func init() {
	app.Commands = append(app.Commands, &cli.Command{
		Name:      "promote",
		Usage:     "promote keys from one environment vault to another",
		ArgsUsage: "<src-env-file> <dst-env-file>",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "overwrite",
				Aliases: []string{"f"},
				Usage:   "overwrite existing keys in destination",
			},
			&cli.StringFlag{
				Name:    "recipient",
				Aliases: []string{"r"},
				Usage:   "additional age recipient public key for destination",
			},
		},
		Action: runPromote,
	})
}

func runPromote(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: envault promote <src-env-file> <dst-env-file>")
	}

	srcEnv := c.Args().Get(0)
	dstEnv := c.Args().Get(1)
	overwrite := c.Bool("overwrite")

	ks, err := keystore.New(mustHomeDir())
	if err != nil {
		return fmt.Errorf("open keystore: %w", err)
	}

	identity, err := ks.Load()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	recipients := []interface{ String() string }{identity.Recipient()}
	_ = recipients // cast handled below

	v, err := vault.New(".")
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	result, err := v.Promote(srcEnv, dstEnv, identity, []interface{ String() string }{identity.Recipient()}, overwrite)
	if err != nil {
		return fmt.Errorf("promote: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Promoted %s → %s\n", result.SourceEnv, result.DestEnv)
	fmt.Fprintf(os.Stdout, "  Added:   %d\n", result.Added)
	fmt.Fprintf(os.Stdout, "  Skipped: %d\n", result.Skipped)
	return nil
}
