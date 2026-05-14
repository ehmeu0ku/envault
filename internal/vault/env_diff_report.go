package vault

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"filippo.io/age"
)

// DiffReportFormat controls the output format of a diff report.
type DiffReportFormat string

const (
	DiffReportText DiffReportFormat = "text"
	DiffReportJSON DiffReportFormat = "json"
)

// DiffReport generates a human-readable or JSON diff between two sealed .env files.
func DiffReport(vaultDir, fileA, fileB string, identity age.Identity, format DiffReportFormat, w io.Writer) error {
	pairsA, err := decryptEnvPairs(vaultDir, fileA, identity)
	if err != nil {
		return fmt.Errorf("reading %s: %w", fileA, err)
	}
	pairsB, err := decryptEnvPairs(vaultDir, fileB, identity)
	if err != nil {
		return fmt.Errorf("reading %s: %w", fileB, err)
	}

	mapA := pairsToMap(pairsA)
	mapB := pairsToMap(pairsB)

	type entry struct {
		Key    string
		Status string
		Old    string
		New    string
	}

	var entries []entry
	allKeys := make(map[string]struct{})
	for k := range mapA {
		allKeys[k] = struct{}{}
	}
	for k := range mapB {
		allKeys[k] = struct{}{}
	}

	keys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		vA, inA := mapA[k]
		vB, inB := mapB[k]
		switch {
		case inA && !inB:
			entries = append(entries, entry{k, "removed", vA, ""})
		case !inA && inB:
			entries = append(entries, entry{k, "added", "", vB})
		case vA != vB:
			entries = append(entries, entry{k, "changed", vA, vB})
		}
	}

	if format == DiffReportJSON {
		fmt.Fprint(w, "[")
		for i, e := range entries {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"key":%q,"status":%q,"old":%q,"new":%q}`, e.Key, e.Status, e.Old, e.New)
		}
		fmt.Fprintln(w, "]")
		return nil
	}

	if len(entries) == 0 {
		fmt.Fprintln(w, "No differences found.")
		return nil
	}
	width := 0
	for _, e := range entries {
		if len(e.Key) > width {
			width = len(e.Key)
		}
	}
	for _, e := range entries {
		pad := strings.Repeat(" ", width-len(e.Key))
		switch e.Status {
		case "added":
			fmt.Fprintf(w, "+ %s%s = %s\n", e.Key, pad, e.New)
		case "removed":
			fmt.Fprintf(w, "- %s%s = %s\n", e.Key, pad, e.Old)
		case "changed":
			fmt.Fprintf(w, "~ %s%s   %s -> %s\n", e.Key, pad, e.Old, e.New)
		}
	}
	return nil
}
