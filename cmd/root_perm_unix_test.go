//go:build unix

package cmd

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestLoadConfigPermissionBitBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        os.FileMode
		defaultFile bool
		reject      bool
	}{
		{"world-write-only", 0o602, false, true},
		{"group-write-only", 0o620, false, true},
		{"group-writable default file", 0o620, true, true},
		{"owner-only", 0o600, false, false},
		{"shared-read-only", 0o644, false, false},
		{"owner-read-only", 0o400, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			name := "config.yaml"
			if tc.defaultFile {
				name = ".pwd-manager.yaml"
			}
			path := writeRootTestConfig(t, home, name, "vault: test\n")
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			var notice bytes.Buffer
			cfg := NewConfig(path)
			if tc.defaultFile {
				cfg.ConfigFile = ""
				cfg.HomeDirFunc = func() (string, error) { return home, nil }
			}
			cfg.Stderr = &notice
			err := LoadConfig(cfg)
			if tc.reject {
				if !errors.Is(err, errInsecureConfigFile) {
					t.Fatalf("LoadConfig mode %#o = %v, want wrapped insecure-file error", tc.mode, err)
				}
				if notice.Len() != 0 || cfg.ConfigFileUsed != "" {
					t.Fatalf("rejected file published as loaded: notice=%q path=%q", notice.String(), cfg.ConfigFileUsed)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig mode %#o: %v", tc.mode, err)
			}
			if cfg.ConfigFileUsed != path {
				t.Fatalf("ConfigFileUsed = %q, want %q", cfg.ConfigFileUsed, path)
			}
		})
	}
}
