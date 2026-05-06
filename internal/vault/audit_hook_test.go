package vault

import (
	"errors"
	"testing"
)

func TestWithAudit_SuccessRecorded(t *testing.T) {
	dir := tempAuditDir(t)
	err := WithAudit(dir, "seal", "prod.env", func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	log, _ := LoadAuditLog(dir)
	if len(log.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(log.Events))
	}
	if !log.Events[0].Success {
		t.Errorf("expected success=true")
	}
	if log.Events[0].Operation != "seal" {
		t.Errorf("operation: got %q, want %q", log.Events[0].Operation, "seal")
	}
}

func TestWithAudit_FailureRecorded(t *testing.T) {
	dir := tempAuditDir(t)
	wantErr := errors.New("encryption failed")
	err := WithAudit(dir, "seal", "prod.env", func() error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error, got %v", err)
	}
	log, _ := LoadAuditLog(dir)
	if len(log.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(log.Events))
	}
	ev := log.Events[0]
	if ev.Success {
		t.Errorf("expected success=false")
	}
	if ev.Message != "encryption failed" {
		t.Errorf("message: got %q, want %q", ev.Message, "encryption failed")
	}
}

func TestWithAudit_ReturnsOriginalError(t *testing.T) {
	dir := tempAuditDir(t)
	sentinel := errors.New("sentinel")
	err := WithAudit(dir, "unseal", "prod.env", func() error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}
