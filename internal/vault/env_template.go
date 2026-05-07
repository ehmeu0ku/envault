package vault

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// TemplateEntry represents a single entry in an env template file.
type TemplateEntry struct {
	Key      string
	Comment  string
	Required bool
}

// GenerateTemplate reads a plaintext .env file and produces a .env.template
// file containing only the keys (no values), with optional inline comments
// preserved. Required keys are annotated with a # required marker.
func GenerateTemplate(envPath, templatePath string) error {
	entries, err := parseTemplateEntries(envPath)
	if err != nil {
		return fmt.Errorf("read env file: %w", err)
	}

	out, err := os.OpenFile(templatePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create template file: %w", err)
	}
	defer out.Close()

	w := bufio.NewWriter(out)
	for _, e := range entries {
		if e.Comment != "" {
			_, _ = fmt.Fprintf(w, "# %s\n", e.Comment)
		}
		if e.Required {
			_, _ = fmt.Fprintf(w, "%s= # required\n", e.Key)
		} else {
			_, _ = fmt.Fprintf(w, "%s=\n", e.Key)
		}
	}
	return w.Flush()
}

// ValidateAgainstTemplate checks that all keys defined in templatePath are
// present in envPath. It returns a list of missing required keys.
func ValidateAgainstTemplate(templatePath, envPath string) ([]string, error) {
	entries, err := parseTemplateEntries(templatePath)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}

	envPairs, err := readEnvPairs(envPath)
	if err != nil {
		return nil, fmt.Errorf("read env file: %w", err)
	}

	envKeys := make(map[string]struct{}, len(envPairs))
	for _, p := range envPairs {
		envKeys[p[0]] = struct{}{}
	}

	var missing []string
	for _, e := range entries {
		if e.Required {
			if _, ok := envKeys[e.Key]; !ok {
				missing = append(missing, e.Key)
			}
		}
	}
	return missing, nil
}

func parseTemplateEntries(path string) ([]TemplateEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []TemplateEntry
	var pendingComment string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			pendingComment = ""
			continue
		}
		if strings.HasPrefix(line, "#") {
			pendingComment = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 1 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		rhs := ""
		if len(parts) == 2 {
			rhs = parts[1]
		}
		required := strings.Contains(rhs, "# required")
		entries = append(entries, TemplateEntry{
			Key:      key,
			Comment:  pendingComment,
			Required: required,
		})
		pendingComment = ""
	}
	return entries, scanner.Err()
}
