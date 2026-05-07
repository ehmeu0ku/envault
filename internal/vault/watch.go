package vault

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"

	"filippo.io/age"
)

// WatchResult describes a change detected on a plain .env file.
type WatchResult struct {
	Path    string
	Changed bool
	Err     error
}

// Watch polls the given plain .env file at the given interval and calls onChange
// whenever its content hash differs from the currently sealed version.
// It returns when ctx is cancelled (caller passes a done channel).
func Watch(
	plainPath string,
	interval time.Duration,
	recipients []age.Recipient,
	identities []age.Identity,
	onChange func(WatchResult),
	done <-chan struct{},
) {
	lastHash, _ := hashFile(plainPath)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			currentHash, err := hashFile(plainPath)
			if err != nil {
				onChange(WatchResult{Path: plainPath, Changed: false, Err: err})
				continue
			}
			if currentHash != lastHash {
				lastHash = currentHash
				v := New(os.TempDir(), recipients, identities)
				if sealErr := v.Seal(plainPath); sealErr != nil {
					onChange(WatchResult{Path: plainPath, Changed: true, Err: sealErr})
				} else {
					onChange(WatchResult{Path: plainPath, Changed: true, Err: nil})
				}
			}
		}
	}
}

// hashFile returns a hex SHA-256 digest of the file at path.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
