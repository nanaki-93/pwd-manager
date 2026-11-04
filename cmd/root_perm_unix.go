//go:build unix

package cmd

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// errInsecureConfigFile reports a config file that other local users could tamper with.
var errInsecureConfigFile = errors.New("insecure config file")

// checkConfigFilePermissions rejects config files not owned by the current user
// or writable by group or others.
func checkConfigFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config file: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		return fmt.Errorf("%w: mode %#o is group- or world-writable", errInsecureConfigFile, mode)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot determine file owner", errInsecureConfigFile)
	}
	if uid := os.Getuid(); int(st.Uid) != uid {
		return fmt.Errorf("%w: owned by uid %d, want %d", errInsecureConfigFile, st.Uid, uid)
	}
	return nil
}
