package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func tempHookVault(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "envault-hook-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestInstallHook_CreatesExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook execution not supported on windows")
	}
	dir := tempHookVault(t)
	err := InstallHook(dir, HookPostSeal, "#!/bin/sh\necho sealed")
	if err != nil {
		t.Fatalf("InstallHook: %v", err)
	}
	script := filepath.Join(hookDir(dir), string(HookPostSeal))
	info, err := os.Stat(script)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("hook script is not executable")
	}
}

func TestRunHook_MissingIsNoop(t *testing.T) {
	dir := tempHookVault(t)
	if err := RunHook(dir, HookPreSeal, ".env"); err != nil {
		t.Errorf("expected no error for missing hook, got: %v", err)
	}
}

func TestRunHook_ExecutesScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook execution not supported on windows")
	}
	dir := tempHookVault(t)
	marker := filepath.Join(dir, "ran")
	script := "#!/bin/sh\ntouch " + marker
	if err := InstallHook(dir, HookPostUnseal, script); err != nil {
		t.Fatal(err)
	}
	if err := RunHook(dir, HookPostUnseal, ".env"); err != nil {
		t.Fatalf("RunHook: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("hook script did not execute (marker file missing)")
	}
}

func TestListHooks_Empty(t *testing.T) {
	dir := tempHookVault(t)
	hooks, err := ListHooks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 0 {
		t.Errorf("expected 0 hooks, got %d", len(hooks))
	}
}

func TestListHooks_AfterInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook execution not supported on windows")
	}
	dir := tempHookVault(t)
	for _, ev := range []HookEvent{HookPreSeal, HookPostSeal} {
		if err := InstallHook(dir, ev, "#!/bin/sh\ntrue"); err != nil {
			t.Fatal(err)
		}
	}
	hooks, err := ListHooks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 2 {
		t.Errorf("expected 2 hooks, got %d", len(hooks))
	}
}
