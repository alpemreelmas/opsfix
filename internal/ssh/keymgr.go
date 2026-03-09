package ssh

import (
	"fmt"
	"os"
)

// ValidateKeyFile checks that the private key file has secure permissions.
// Fails if key is group- or world-readable (mode & 0o044 != 0).
func ValidateKeyFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("ssh key %q: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode&0o044 != 0 {
		return fmt.Errorf("ssh key %q: permissions %04o are too open; require 0600 or 0400", path, mode)
	}
	return nil
}
