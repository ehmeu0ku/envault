package vault

import (
	"path/filepath"
	"testing"
)

func TestSignFile_MultipleFiles(t *testing.T) {
	dir := tempSignDir(t)
	key := []byte("supersecretkey32byteslong!!!!!!!")

	files := []string{"dev.env.age", "prod.env.age", "staging.env.age"}
	for _, name := range files {
		path := writeSignFile(t, dir, name, "content-for-"+name)
		if err := SignFile(dir, path, key); err != nil {
			t.Fatalf("SignFile(%s): %v", name, err)
		}
	}

	records, err := LoadSignatures(dir)
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}
	if len(records) != len(files) {
		t.Errorf("expected %d records, got %d", len(files), len(records))
	}

	for _, name := range files {
		path := filepath.Join(dir, name)
		if err := VerifySignature(dir, path, key); err != nil {
			t.Errorf("VerifySignature(%s): %v", name, err)
		}
	}
}

func TestSignFile_OverwritesExistingRecord(t *testing.T) {
	dir := tempSignDir(t)
	path := writeSignFile(t, dir, "dev.env.age", "original")
	key := []byte("supersecretkey32byteslong!!!!!!!")

	if err := SignFile(dir, path, key); err != nil {
		t.Fatalf("first SignFile: %v", err)
	}

	recordsBefore, _ := LoadSignatures(dir)
	sigBefore := recordsBefore["dev.env.age"].Signature

	// Update file content and re-sign
	writeSignFile(t, dir, "dev.env.age", "updated-content")
	if err := SignFile(dir, path, key); err != nil {
		t.Fatalf("second SignFile: %v", err)
	}

	recordsAfter, _ := LoadSignatures(dir)
	sigAfter := recordsAfter["dev.env.age"].Signature

	if sigBefore == sigAfter {
		t.Error("expected signature to change after content update")
	}

	if len(recordsAfter) != 1 {
		t.Errorf("expected 1 record after overwrite, got %d", len(recordsAfter))
	}
}

func TestSignFile_RecordContainsRelativePath(t *testing.T) {
	dir := tempSignDir(t)
	path := writeSignFile(t, dir, "ci.env.age", "data")
	key := []byte("supersecretkey32byteslong!!!!!!!")

	if err := SignFile(dir, path, key); err != nil {
		t.Fatalf("SignFile: %v", err)
	}

	records, _ := LoadSignatures(dir)
	if _, ok := records["ci.env.age"]; !ok {
		t.Errorf("expected relative key 'ci.env.age', got keys: %v", records)
	}
}
