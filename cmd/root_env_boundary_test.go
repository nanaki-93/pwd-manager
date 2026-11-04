package cmd

import (
	"io"
	"testing"
)

func TestLoadConfigEnvironmentWithoutDefaultFile(t *testing.T) {
	t.Setenv("VAULT", "unprefixed-vault")
	t.Setenv("PROFILE", "unprefixed-profile")
	t.Setenv("PWD_MANAGER_VAULT", "namespaced-vault")
	t.Setenv("PWD_MANAGER_PROFILE", "namespaced-profile")
	t.Setenv("PWD_MANAGER_UNLISTED_BOUNDARY_KEY", "unexpected")
	home := t.TempDir()
	cfg := NewConfig("")
	cfg.HomeDirFunc = func() (string, error) { return home, nil }
	cfg.Stderr = io.Discard
	if err := LoadConfig(cfg); err != nil {
		t.Fatalf("LoadConfig without default file: %v", err)
	}
	for key, want := range map[string]string{
		"vault":                 "namespaced-vault",
		"profile":               "namespaced-profile",
		"unlisted_boundary_key": "",
	} {
		if got := cfg.Viper.GetString(key); got != want {
			t.Errorf("config %q = %q, want %q", key, got, want)
		}
	}
	if cfg.ConfigFileUsed != "" {
		t.Fatalf("missing default file reported as loaded: %q", cfg.ConfigFileUsed)
	}
}
