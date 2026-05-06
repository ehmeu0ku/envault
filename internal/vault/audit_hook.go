package vault

// WithAudit wraps a vault operation function, recording the result to the
// audit log stored in vaultDir.
//
// Usage:
//
//	err := WithAudit(vaultDir, "seal", target, func() error {
//	    return v.Seal(target)
//	})
func WithAudit(vaultDir, operation, target string, fn func() error) error {
	err := fn()
	success := err == nil
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	// Best-effort: ignore audit write errors so the primary operation
	// result is always returned to the caller.
	_ = AppendAuditEvent(vaultDir, operation, target, success, msg)
	return err
}
