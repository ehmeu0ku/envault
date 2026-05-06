package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const tagFileName = ".envault-tags.json"

// tagIndex maps encrypted file paths (relative to vault dir) to a list of tags.
type tagIndex map[string][]string

func tagIndexPath(vaultDir string) string {
	return filepath.Join(vaultDir, tagFileName)
}

// LoadTags reads the tag index for the given vault directory.
// Returns an empty index if the file does not exist.
func LoadTags(vaultDir string) (tagIndex, error) {
	path := tagIndexPath(vaultDir)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(tagIndex), nil
	}
	if err != nil {
		return nil, err
	}
	var idx tagIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, err
	}
	return idx, nil
}

// SaveTags persists the tag index to disk.
func SaveTags(vaultDir string, idx tagIndex) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(tagIndexPath(vaultDir), data, 0600)
}

// AddTag adds a tag to the given file entry in the index.
// Duplicate tags are silently ignored.
func AddTag(idx tagIndex, file, tag string) {
	for _, t := range idx[file] {
		if t == tag {
			return
		}
	}
	idx[file] = append(idx[file], tag)
}

// RemoveTag removes a tag from the given file entry in the index.
func RemoveTag(idx tagIndex, file, tag string) {
	tags := idx[file]
	updated := tags[:0]
	for _, t := range tags {
		if t != tag {
			updated = append(updated, t)
		}
	}
	idx[file] = updated
}

// FindByTag returns all file keys that carry the given tag.
func FindByTag(idx tagIndex, tag string) []string {
	var matches []string
	for file, tags := range idx {
		for _, t := range tags {
			if t == tag {
				matches = append(matches, file)
				break
			}
		}
	}
	return matches
}
