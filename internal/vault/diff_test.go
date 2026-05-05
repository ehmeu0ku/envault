package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeDiff_NoChanges(t *testing.T) {
	plain := map[string]string{"FOO": "bar", "BAZ": "qux"}
	enc := map[string]string{"FOO": "bar", "BAZ": "qux"}

	result := computeDiff(plain, enc)

	if result.HasChanges() {
		t.Errorf("expected no changes, got: %+v", result)
	}
	if len(result.Unchanged) != 2 {
		t.Errorf("expected 2 unchanged keys, got %d", len(result.Unchanged))
	}
}

func TestComputeDiff_Modified(t *testing.T) {
	plain := map[string]string{"FOO": "bar"}
	enc := map[string]string{"FOO": "changed"}

	result := computeDiff(plain, enc)

	if len(result.Modified) != 1 || result.Modified[0] != "FOO" {
		t.Errorf("expected FOO in Modified, got %+v", result)
	}
}

func TestComputeDiff_OnlyInPlain(t *testing.T) {
	plain := map[string]string{"NEW_KEY": "val", "SHARED": "x"}
	enc := map[string]string{"SHARED": "x"}

	result := computeDiff(plain, enc)

	if len(result.OnlyInPlain) != 1 || result.OnlyInPlain[0] != "NEW_KEY" {
		t.Errorf("expected NEW_KEY only in plain, got %+v", result)
	}
}

func TestComputeDiff_OnlyInEncrypted(t *testing.T) {
	plain := map[string]string{"SHARED": "x"}
	enc := map[string]string{"SHARED": "x", "OLD_KEY": "gone"}

	result := computeDiff(plain, enc)

	if len(result.OnlyInEncrypted) != 1 || result.OnlyInEncrypted[0] != "OLD_KEY" {
		t.Errorf("expected OLD_KEY only in encrypted, got %+v", result)
	}
}

func TestParseEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	content := `# comment
FOO=bar
BAZ=hello=world

EMPTY=
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	result, err := parseEnvFile(path)
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}

	cases := map[string]string{
		"FOO":   "bar",
		"BAZ":   "hello=world",
		"EMPTY": "",
	}
	for k, want := range cases {
		got, ok := result[k]
		if !ok {
			t.Errorf("key %q not found in parsed result", k)
			continue
		}
		if got != want {
			t.Errorf("key %q: want %q, got %q", k, want, got)
		}
	}
	if _, ok := result["# comment"]; ok {
		t.Error("comment line should not be parsed as a key")
	}
}
