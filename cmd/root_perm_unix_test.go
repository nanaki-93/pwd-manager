//go:build unix

package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigRejectsWorldWritableConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vault: test\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Chmod(cfgPath, 0o666); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	cfg := NewConfig(cfgPath)
	cfg.Stderr = io.Discard
	if err := LoadConfig(cfg); err == nil {
		t.Fatalf("LoadConfig error = nil for mode 0666 config, want rejection")
	}
	if cfg.ConfigFileUsed != "" {
		t.Fatalf("ConfigFileUsed = %q, want empty on rejection", cfg.ConfigFileUsed)
	}
}

func TestLoadConfigRejectsGroupWritableDefaultConfig(t *testing.T) {
	home := t.TempDir()
	cfgPath := filepath.Join(home, ".pwd-manager.yaml")
	if err := os.WriteFile(cfgPath, []byte("vault: test\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Chmod(cfgPath, 0o620); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	cfg := NewConfig("")
	cfg.HomeDirFunc = func() (string, error) { return home, nil }
	cfg.Stderr = io.Discard
	if err := LoadConfig(cfg); err == nil {
		t.Fatalf("LoadConfig error = nil for mode 0620 config, want rejection")
	}
}

func TestLoadConfigAcceptsOwnerOnlyConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vault: test\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg := NewConfig(cfgPath)
	cfg.Stderr = io.Discard
	if err := LoadConfig(cfg); err != nil {
		t.Fatalf("LoadConfig error = %v, want nil", err)
	}
}
