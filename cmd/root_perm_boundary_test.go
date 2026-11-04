//go:build unix

package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigPermissionBitBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   os.FileMode
		reject bool
	}{
		{"world-write-only", 0o602, true},
		{"group-write-only", 0o620, true},
		{"shared-read-only", 0o644, false},
		{"owner-read-only", 0o400, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("vault: test\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			var notice bytes.Buffer
			cfg := NewConfig(path)
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
