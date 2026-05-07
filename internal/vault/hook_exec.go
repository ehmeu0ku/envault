package vault

import (
	"fmt"
	"os/exec"
)

// runScript executes the given script file with args and returns a combined
// error containing stdout+stderr on failure.
func runScript(script string, args ...string) error {
	cmd := exec.Command(script, args...) // #nosec G204
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hook %q failed: %w\noutput: %s", script, err, string(out))
	}
	return nil
}
