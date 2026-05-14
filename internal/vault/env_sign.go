package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SignatureRecord holds the HMAC-SHA256 signature of a sealed vault file.
type SignatureRecord struct {
	File      string    `json:"file"`
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
}

func signIndexPath(vaultDir string) string {
	return filepath.Join(vaultDir, ".envault", "signatures.json")
}

// SignFile computes an HMAC-SHA256 over the encrypted file contents using the
// provided key and persists the record to the vault signature index.
func SignFile(vaultDir, encFile string, key []byte) error {
	data, err := os.ReadFile(encFile)
	if err != nil {
		return fmt.Errorf("sign: read file: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sig := hex.EncodeToString(mac.Sum(nil))

	records, err := LoadSignatures(vaultDir)
	if err != nil {
		return err
	}

	rel, _ := filepath.Rel(vaultDir, encFile)
	records[rel] = SignatureRecord{
		File:      rel,
		Signature: sig,
		SignedAt:  time.Now().UTC(),
	}
	return saveSignatures(vaultDir, records)
}

// VerifySignature checks the HMAC-SHA256 of encFile against the stored record.
func VerifySignature(vaultDir, encFile string, key []byte) error {
	records, err := LoadSignatures(vaultDir)
	if err != nil {
		return err
	}
	rel, _ := filepath.Rel(vaultDir, encFile)
	rec, ok := records[rel]
	if !ok {
		return fmt.Errorf("sign: no signature found for %s", rel)
	}

	data, err := os.ReadFile(encFile)
	if err != nil {
		return fmt.Errorf("sign: read file: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(rec.Signature)) {
		return fmt.Errorf("sign: signature mismatch for %s", rel)
	}
	return nil
}

// LoadSignatures returns all stored signature records for a vault directory.
func LoadSignatures(vaultDir string) (map[string]SignatureRecord, error) {
	path := signIndexPath(vaultDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]SignatureRecord{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sign: load index: %w", err)
	}
	var records map[string]SignatureRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("sign: parse index: %w", err)
	}
	return records, nil
}

func saveSignatures(vaultDir string, records map[string]SignatureRecord) error {
	path := signIndexPath(vaultDir)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("sign: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("sign: marshal: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
