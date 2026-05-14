package vault

import (
	"fmt"
	"sort"

	"filippo.io/age"
)

// CompareResult holds the result of comparing two vault files.
type CompareResult struct {
	OnlyInA    []string          // keys only in file A
	OnlyInB    []string          // keys only in file B
	Different  []string          // keys present in both but with different values
	Identical  []string          // keys present in both with identical values
}

// Summary returns a human-readable one-line summary of the comparison.
func (r CompareResult) Summary() string {
	return fmt.Sprintf("+%d -%d ~%d =%d",
		len(r.OnlyInB), len(r.OnlyInA), len(r.Different), len(r.Identical))
}

// Compare decrypts two encrypted .env files and compares their key-value pairs.
func (v *Vault) Compare(pathA, pathB string, identity age.Identity) (CompareResult, error) {
	pairsA, err := v.decryptToPairs(pathA, identity)
	if err != nil {
		return CompareResult{}, fmt.Errorf("reading %s: %w", pathA, err)
	}
	pairsB, err := v.decryptToPairs(pathB, identity)
	if err != nil {
		return CompareResult{}, fmt.Errorf("reading %s: %w", pathB, err)
	}

	mapA := make(map[string]string, len(pairsA))
	for _, p := range pairsA {
		mapA[p[0]] = p[1]
	}
	mapB := make(map[string]string, len(pairsB))
	for _, p := range pairsB {
		mapB[p[0]] = p[1]
	}

	var result CompareResult
	for k, vA := range mapA {
		if vB, ok := mapB[k]; !ok {
			result.OnlyInA = append(result.OnlyInA, k)
		} else if vA != vB {
			result.Different = append(result.Different, k)
		} else {
			result.Identical = append(result.Identical, k)
		}
	}
	for k := range mapB {
		if _, ok := mapA[k]; !ok {
			result.OnlyInB = append(result.OnlyInB, k)
		}
	}

	sort.Strings(result.OnlyInA)
	sort.Strings(result.OnlyInB)
	sort.Strings(result.Different)
	sort.Strings(result.Identical)
	return result, nil
}

// decryptToPairs decrypts an age-encrypted .env file and returns key=value pairs.
func (v *Vault) decryptToPairs(path string, identity age.Identity) ([][2]string, error) {
	plain, err := v.UnsealToMemory(path, identity)
	if err != nil {
		return nil, err
	}
	return parseEnvFile(plain), nil
}
