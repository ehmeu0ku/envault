package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HookEvent represents the lifecycle point at which a hook fires.
type HookEvent string

const (
	HookPreSeal   HookEvent = "pre-seal"
	HookPostSeal  HookEvent = "post-seal"
	HookPreUnseal HookEvent = "pre-unseal"
	HookPostUnseal HookEvent = "post-unseal"
)

// hookDir returns the directory where hook scripts are stored.
func hookDir(vaultDir string) string {
	return filepath.Join(vaultDir, ".envault", "hooks")
}

// RunHook executes any executable script found at
// <vaultDir>/.envault/hooks/<event> passing envFile as the first argument.
// Missing hook scripts are silently ignored.
func RunHook(vaultDir string, event HookEvent, envFile string) error {
	script := filepath.Join(hookDir(vaultDir), string(event))

	info, err := os.Stat(script)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("hook stat: %w", err)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("hook %s exists but is not executable", script)
	}

	return runScript(script, envFile)
}

// InstallHook writes a hook script to the hooks directory.
// content should be a valid shell script (or any executable text).
func InstallHook(vaultDir string, event HookEvent, content string) error {
	dir := hookDir(vaultDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create hook dir: %w", err)
	}
	script := filepath.Join(dir, string(event))
	if err := os.WriteFile(script, []byte(strings.TrimSpace(content)+"\n"), 0o700); err != nil {
		return fmt.Errorf("write hook: %w", err)
	}
	return nil
}

// ListHooks returns all installed hook events for the given vault directory.
func ListHooks(vaultDir string) ([]HookEvent, error) {
	dir := hookDir(vaultDir)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read hook dir: %w", err)
	}
	var events []HookEvent
	for _, e := range entries {
		if !e.IsDir() {
			events = append(events, HookEvent(e.Name()))
		}
	}
	return events, nil
}
