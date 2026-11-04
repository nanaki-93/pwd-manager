//go:build !unix

package cmd

import (
	"fmt"
	"os"
)

// checkConfigFilePermissions verifies the config file exists; POSIX ownership
// and mode bits are not meaningful on this platform.
func checkConfigFilePermissions(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("stat config file: %w", err)
	}
	return nil
}
