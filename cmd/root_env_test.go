package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeEnvTestConfig(t *testing.T) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vault: test\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

func TestLoadConfigIgnoresUnprefixedEnv(t *testing.T) {
	t.Setenv("VAULT", "attacker")
	cfg := NewConfig(writeEnvTestConfig(t))
	cfg.Stderr = io.Discard
	if err := LoadConfig(cfg); err != nil {
		t.Fatalf("LoadConfig error = %v, want nil", err)
	}
	if got := cfg.Viper.GetString("vault"); got != "test" {
		t.Fatalf("vault = %q, want file value %q (unprefixed env must not override)", got, "test")
	}
}

func TestLoadConfigHonorsPrefixedEnv(t *testing.T) {
	t.Setenv("PWD_MANAGER_VAULT", "override")
	cfg := NewConfig(writeEnvTestConfig(t))
	cfg.Stderr = io.Discard
	if err := LoadConfig(cfg); err != nil {
		t.Fatalf("LoadConfig error = %v, want nil", err)
	}
	if got := cfg.Viper.GetString("vault"); got != "override" {
		t.Fatalf("vault = %q, want %q from PWD_MANAGER_VAULT", got, "override")
	}
}
