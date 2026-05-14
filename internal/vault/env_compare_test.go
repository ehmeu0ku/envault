package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/nicholasgasior/envault/internal/vault"
)

func generateCompareTestIdentity(t *testing.T) age.Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func sealCompareEnv(t *testing.T, v *vault.Vault, id age.Identity, name, content string) string {
	t.Helper()
	plainPath := filepath.Join(t.TempDir(), name+".env")
	if err := os.WriteFile(plainPath, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	recipient, ok := id.(*age.X25519Identity)
	if !ok {
		t.Fatal("identity is not X25519Identity")
	}
	encPath, err := v.Seal(plainPath, recipient)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return encPath
}

func TestCompare_IdenticalFiles(t *testing.T) {
	v := tempVault(t)
	id := generateCompareTestIdentity(t)
	content := "FOO=bar\nBAZ=qux\n"
	pathA := sealCompareEnv(t, v, id, "a", content)
	pathB := sealCompareEnv(t, v, id, "b", content)

	result, err := v.Compare(pathA, pathB, id)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(result.Identical) != 2 {
		t.Errorf("expected 2 identical, got %d", len(result.Identical))
	}
	if len(result.Different) != 0 || len(result.OnlyInA) != 0 || len(result.OnlyInB) != 0 {
		t.Errorf("unexpected diff: %+v", result)
	}
}

func TestCompare_DifferentValues(t *testing.T) {
	v := tempVault(t)
	id := generateCompareTestIdentity(t)
	pathA := sealCompareEnv(t, v, id, "a", "FOO=old\nSHARED=same\n")
	pathB := sealCompareEnv(t, v, id, "b", "FOO=new\nSHARED=same\n")

	result, err := v.Compare(pathA, pathB, id)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(result.Different) != 1 || result.Different[0] != "FOO" {
		t.Errorf("expected Different=[FOO], got %v", result.Different)
	}
	if len(result.Identical) != 1 || result.Identical[0] != "SHARED" {
		t.Errorf("expected Identical=[SHARED], got %v", result.Identical)
	}
}

func TestCompare_DisjointKeys(t *testing.T) {
	v := tempVault(t)
	id := generateCompareTestIdentity(t)
	pathA := sealCompareEnv(t, v, id, "a", "ONLY_A=1\n")
	pathB := sealCompareEnv(t, v, id, "b", "ONLY_B=2\n")

	result, err := v.Compare(pathA, pathB, id)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(result.OnlyInA) != 1 || result.OnlyInA[0] != "ONLY_A" {
		t.Errorf("OnlyInA: %v", result.OnlyInA)
	}
	if len(result.OnlyInB) != 1 || result.OnlyInB[0] != "ONLY_B" {
		t.Errorf("OnlyInB: %v", result.OnlyInB)
	}
}

func TestCompare_Summary(t *testing.T) {
	r := vault.CompareResult{
		OnlyInA:   []string{"X"},
		OnlyInB:   []string{"Y", "Z"},
		Different: []string{"W"},
		Identical: []string{},
	}
	got := r.Summary()
	expected := "+2 -1 ~1 =0"
	if got != expected {
		t.Errorf("Summary() = %q, want %q", got, expected)
	}
}
