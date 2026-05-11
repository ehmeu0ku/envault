package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nicholasgasior/envault/internal/crypto"
	"filippo.io/age"
)

// MergeStrategy controls how key conflicts are resolved during merge.
type MergeStrategy int

const (
	// MergeStrategySkip keeps the destination value on conflict.
	MergeStrategySkip MergeStrategy = iota
	// MergeStrategyOverwrite replaces destination value with source on conflict.
	MergeStrategyOverwrite
)

// MergeResult holds a summary of the merge operation.
type MergeResult struct {
	Added    []string
	Skipped  []string
	Overwritten []string
}

// Merge decrypts src and dst .env.age files, merges key-value pairs according
// to the given strategy, then re-encrypts the result into dst.
func (v *Vault) Merge(src, dst string, identity age.Identity, recipient age.Recipient, strategy MergeStrategy) (MergeResult, error) {
	srcEnc := encryptedPath(src)
	dstEnc := encryptedPath(dst)

	if _, err := os.Stat(srcEnc); err != nil {
		return MergeResult{}, fmt.Errorf("merge: source file not found: %w", err)
	}
	if _, err := os.Stat(dstEnc); err != nil {
		return MergeResult{}, fmt.Errorf("merge: destination file not found: %w", err)
	}

	srcTmp, err := os.CreateTemp("", "envault-merge-src-*")
	if err != nil {
		return MergeResult{}, err
	}
	defer os.Remove(srcTmp.Name())
	srcTmp.Close()

	dstTmp, err := os.CreateTemp("", "envault-merge-dst-*")
	if err != nil {
		return MergeResult{}, err
	}
	defer os.Remove(dstTmp.Name())
	dstTmp.Close()

	if err := crypto.DecryptFile(srcEnc, srcTmp.Name(), identity); err != nil {
		return MergeResult{}, fmt.Errorf("merge: decrypt source: %w", err)
	}
	if err := crypto.DecryptFile(dstEnc, dstTmp.Name(), identity); err != nil {
		return MergeResult{}, fmt.Errorf("merge: decrypt destination: %w", err)
	}

	srcPairs, err := readEnvPairs(srcTmp.Name())
	if err != nil {
		return MergeResult{}, fmt.Errorf("merge: parse source: %w", err)
	}
	dstPairs, err := readEnvPairs(dstTmp.Name())
	if err != nil {
		return MergeResult{}, fmt.Errorf("merge: parse destination: %w", err)
	}

	dstMap := make(map[string]string, len(dstPairs))
	for _, p := range dstPairs {
		dstMap[p[0]] = p[1]
	}

	var result MergeResult
	for _, p := range srcPairs {
		key, val := p[0], p[1]
		if _, exists := dstMap[key]; exists {
			if strategy == MergeStrategyOverwrite {
				dstMap[key] = val
				result.Overwritten = append(result.Overwritten, key)
			} else {
				result.Skipped = append(result.Skipped, key)
			}
		} else {
			dstMap[key] = val
			result.Added = append(result.Added, key)
		}
	}

	mergedTmp, err := os.CreateTemp("", "envault-merge-out-*")
	if err != nil {
		return MergeResult{}, err
	}
	defer os.Remove(mergedTmp.Name())

	for k, v2 := range dstMap {
		fmt.Fprintf(mergedTmp, "%s=%s\n", k, v2)
	}
	mergedTmp.Close()

	if err := os.MkdirAll(filepath.Dir(dstEnc), 0o700); err != nil {
		return MergeResult{}, err
	}
	if err := crypto.EncryptFile(mergedTmp.Name(), dstEnc, recipient); err != nil {
		return MergeResult{}, fmt.Errorf("merge: re-encrypt destination: %w", err)
	}

	return result, nil
}
