package vault

import (
	"encoding/hex"
	"testing"
)

func TestSaveAndLoadSignatures_Roundtrip(t *testing.T) {
	dir := tempSignDir(t)
	key := []byte("supersecretkey32byteslong!!!!!!!")
	path := writeSignFile(t, dir, "roundtrip.env.age", "hello world")

	if err := SignFile(dir, path, key); err != nil {
		t.Fatalf("SignFile: %v", err)
	}

	records, err := LoadSignatures(dir)
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}

	rec, ok := records["roundtrip.env.age"]
	if !ok {
		t.Fatal("expected record not found")
	}
	if rec.File != "roundtrip.env.age" {
		t.Errorf("File field: got %q", rec.File)
	}
	if rec.Signature == "" {
		t.Error("Signature should not be empty")
	}
	if rec.SignedAt.IsZero() {
		t.Error("SignedAt should not be zero")
	}
	// Verify hex decodability
	if _, err := hex.DecodeString(rec.Signature); err != nil {
		t.Errorf("Signature is not valid hex: %v", err)
	}
}

func TestSignatureLength_IsSHA256(t *testing.T) {
	dir := tempSignDir(t)
	path := writeSignFile(t, dir, "len.env.age", "content")
	key := []byte("supersecretkey32byteslong!!!!!!!")

	if err := SignFile(dir, path, key); err != nil {
		t.Fatalf("SignFile: %v", err)
	}

	records, _ := LoadSignatures(dir)
	rec := records["len.env.age"]

	// SHA-256 produces 32 bytes = 64 hex chars
	const expectedHexLen = 64
	if len(rec.Signature) != expectedHexLen {
		t.Errorf("expected signature length %d, got %d", expectedHexLen, len(rec.Signature))
	}
}

func TestVerifySignature_DifferentVaultDir(t *testing.T) {
	dir1 := tempSignDir(t)
	dir2 := tempSignDir(t)
	key := []byte("supersecretkey32byteslong!!!!!!!")

	path := writeSignFile(t, dir1, "env.age", "data")
	if err := SignFile(dir1, path, key); err != nil {
		t.Fatalf("SignFile: %v", err)
	}

	// Verify against wrong vault dir (no index there)
	if err := VerifySignature(dir2, path, key); err == nil {
		t.Error("expected error when verifying against wrong vault dir")
	}
}
