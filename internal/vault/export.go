package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExportFormat defines the output format for exported secrets.
type ExportFormat string

const (
	FormatDotEnv ExportFormat = "dotenv"
	FormatExport ExportFormat = "export"
	FormatJSON   ExportFormat = "json"
)

// Export decrypts an encrypted .env file and returns its contents
// formatted according to the specified format.
func (v *Vault) Export(name string, format ExportFormat) (string, error) {
	encPath := encryptedPath(v.dir, name)
	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		return "", fmt.Errorf("encrypted file not found: %s", encPath)
	}

	tmpFile, err := os.CreateTemp("", "envault-export-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := v.crypto.DecryptFile(encPath, tmpPath, v.identity); err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return "", fmt.Errorf("read decrypted file: %w", err)
	}

	pairs, err := parseEnvFile(string(data))
	if err != nil {
		return "", fmt.Errorf("parse env file: %w", err)
	}

	return formatOutput(pairs, format)
}

// ExportFile decrypts and writes the formatted output to a destination file.
func (v *Vault) ExportFile(name string, format ExportFormat, dest string) error {
	out, err := v.Export(name, format)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, []byte(out), 0600); err != nil {
		return fmt.Errorf("write export file: %w", err)
	}
	return nil
}

func formatOutput(pairs []envPair, format ExportFormat) (string, error) {
	var sb strings.Builder
	switch format {
	case FormatDotEnv:
		for _, p := range pairs {
			fmt.Fprintf(&sb, "%s=%s\n", p.Key, p.Value)
		}
	case FormatExport:
		for _, p := range pairs {
			fmt.Fprintf(&sb, "export %s=%q\n", p.Key, p.Value)
		}
	case FormatJSON:
		sb.WriteString("{\n")
		for i, p := range pairs {
			comma := ","
			if i == len(pairs)-1 {
				comma = ""
			}
			fmt.Fprintf(&sb, "  %q: %q%s\n", p.Key, p.Value, comma)
		}
		sb.WriteString("}\n")
	default:
		return "", fmt.Errorf("unknown format: %s", format)
	}
	return sb.String(), nil
}

// envPair holds a key-value pair parsed from an env file.
type envPair struct {
	Key   string
	Value string
}

func init() {
	_ = filepath.Join // ensure filepath import used
}
