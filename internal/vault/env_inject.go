package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"filippo.io/age"

	"github.com/vercel/envault/internal/crypto"
)

// InjectOptions controls how environment variables are injected into a subprocess.
type InjectOptions struct {
	Overwrite bool // overwrite existing env vars with vault values
}

// Inject decrypts the sealed env file at envPath and runs the given command
// with the decrypted key=value pairs merged into the process environment.
func Inject(vaultDir, envPath string, identity age.Identity, args []string, opts InjectOptions) error {
	if len(args) == 0 {
		return fmt.Errorf("inject: no command specified")
	}

	enc := encryptedPath(envPath)
	if _, err := os.Stat(enc); os.IsNotExist(err) {
		return fmt.Errorf("inject: encrypted file not found: %s", enc)
	}

	tmpFile, err := os.CreateTemp("", "envault-inject-*.env")
	if err != nil {
		return fmt.Errorf("inject: create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	if err := crypto.DecryptFile(enc, tmpFile.Name(), identity); err != nil {
		return fmt.Errorf("inject: decrypt: %w", err)
	}

	pairs, err := readEnvPairs(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("inject: parse env: %w", err)
	}

	base := os.Environ()
	existing := make(map[string]bool, len(base))
	for _, e := range base {
		parts := strings.SplitN(e, "=", 2)
		existing[parts[0]] = true
	}

	extra := make([]string, 0, len(pairs))
	for _, kv := range pairs {
		if !opts.Overwrite && existing[kv[0]] {
			continue
		}
		extra = append(extra, kv[0]+"="+kv[1])
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(base, extra...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("inject: command failed: %w", err)
	}
	return nil
}
