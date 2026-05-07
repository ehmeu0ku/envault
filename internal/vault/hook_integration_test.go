package vault_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"envault/internal/vault"
)

// TestRunHook_NonExecutableReturnsError ensures a non-executable hook file
// causes an explicit error rather than a silent noop.
func TestRunHook_NonExecutableReturnsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not meaningful on windows")
	}
	dir, err := os.MkdirTemp("", "envault-hook-integ-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	hDir := filepath.Join(dir, ".envault", "hooks")
	if err := os.MkdirAll(hDir, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(hDir, string(vault.HookPreSeal))
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntrue\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := vault.RunHook(dir, vault.HookPreSeal, ".env"); err == nil {
		t.Error("expected error for non-executable hook, got nil")
	}
}

// TestRunHook_FailingScriptReturnsError ensures a hook that exits non-zero
// propagates an error.
func TestRunHook_FailingScriptReturnsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook execution not supported on windows")
	}
	dir, err := os.MkdirTemp("", "envault-hook-fail-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	if err := vault.InstallHook(dir, vault.HookPostSeal, "#!/bin/sh\nexit 1"); err != nil {
		t.Fatal(err)
	}
	if err := vault.RunHook(dir, vault.HookPostSeal, ".env"); err == nil {
		t.Error("expected error from failing hook script, got nil")
	}
}
