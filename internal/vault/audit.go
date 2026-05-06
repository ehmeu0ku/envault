package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AuditEvent represents a single recorded vault operation.
type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Operation string    `json:"operation"`
	Target    string    `json:"target"`
	Success   bool      `json:"success"`
	Message   string    `json:"message,omitempty"`
}

// AuditLog holds a sequence of audit events.
type AuditLog struct {
	Events []AuditEvent `json:"events"`
}

// auditLogPath returns the path to the audit log file for a vault dir.
func auditLogPath(vaultDir string) string {
	return filepath.Join(vaultDir, ".envault_audit.json")
}

// AppendAuditEvent appends a single event to the audit log in vaultDir.
func AppendAuditEvent(vaultDir, operation, target string, success bool, message string) error {
	log, err := LoadAuditLog(vaultDir)
	if err != nil {
		return fmt.Errorf("audit: load: %w", err)
	}
	log.Events = append(log.Events, AuditEvent{
		Timestamp: time.Now().UTC(),
		Operation: operation,
		Target:    target,
		Success:   success,
		Message:   message,
	})
	return saveAuditLog(vaultDir, log)
}

// LoadAuditLog reads the audit log from disk, returning an empty log if absent.
func LoadAuditLog(vaultDir string) (*AuditLog, error) {
	path := auditLogPath(vaultDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &AuditLog{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: read: %w", err)
	}
	var log AuditLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("audit: parse: %w", err)
	}
	return &log, nil
}

// saveAuditLog writes the audit log to disk.
func saveAuditLog(vaultDir string, log *AuditLog) error {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	path := auditLogPath(vaultDir)
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return fmt.Errorf("audit: mkdir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
