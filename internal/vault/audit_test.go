package vault

import (
	"os"
	"testing"
)

func tempAuditDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "envault-audit-*")
	if err != nil {
		t.Fatalf("tempAuditDir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestAuditLog_EmptyOnMissing(t *testing.T) {
	dir := tempAuditDir(t)
	log, err := LoadAuditLog(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(log.Events) != 0 {
		t.Fatalf("expected empty log, got %d events", len(log.Events))
	}
}

func TestAppendAuditEvent_SingleEvent(t *testing.T) {
	dir := tempAuditDir(t)
	if err := AppendAuditEvent(dir, "seal", ".env", true, ""); err != nil {
		t.Fatalf("AppendAuditEvent: %v", err)
	}
	log, err := LoadAuditLog(dir)
	if err != nil {
		t.Fatalf("LoadAuditLog: %v", err)
	}
	if len(log.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(log.Events))
	}
	ev := log.Events[0]
	if ev.Operation != "seal" {
		t.Errorf("operation: got %q, want %q", ev.Operation, "seal")
	}
	if ev.Target != ".env" {
		t.Errorf("target: got %q, want %q", ev.Target, ".env")
	}
	if !ev.Success {
		t.Errorf("expected success=true")
	}
}

func TestAppendAuditEvent_MultipleEvents(t *testing.T) {
	dir := tempAuditDir(t)
	ops := []string{"seal", "unseal", "rotate"}
	for _, op := range ops {
		if err := AppendAuditEvent(dir, op, ".env", true, ""); err != nil {
			t.Fatalf("AppendAuditEvent(%s): %v", op, err)
		}
	}
	log, err := LoadAuditLog(dir)
	if err != nil {
		t.Fatalf("LoadAuditLog: %v", err)
	}
	if len(log.Events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(log.Events))
	}
	for i, op := range ops {
		if log.Events[i].Operation != op {
			t.Errorf("event[%d]: got %q, want %q", i, log.Events[i].Operation, op)
		}
	}
}

func TestAppendAuditEvent_FailureMessage(t *testing.T) {
	dir := tempAuditDir(t)
	if err := AppendAuditEvent(dir, "seal", ".env", false, "file not found"); err != nil {
		t.Fatalf("AppendAuditEvent: %v", err)
	}
	log, _ := LoadAuditLog(dir)
	if log.Events[0].Success {
		t.Errorf("expected success=false")
	}
	if log.Events[0].Message != "file not found" {
		t.Errorf("message: got %q, want %q", log.Events[0].Message, "file not found")
	}
}
