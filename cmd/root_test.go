package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type rootErrWriter struct {
	err error
}

func (w rootErrWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

func TestLoadConfigMissingHomeDirReturnsError(t *testing.T) {
	wantErr := errors.New("home directory unavailable")
	var stderr bytes.Buffer
	cfg := NewConfig("")
	cfg.HomeDirFunc = func() (string, error) {
		return "", wantErr
	}
	cfg.Stderr = &stderr

	err := LoadConfig(cfg)
	if err == nil {
		t.Fatal("expected error when home directory lookup fails, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error %v, got %v", wantErr, err)
	}
}

func TestLoadConfigWithExplicitFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vault: test\n"), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	var stderr bytes.Buffer
	cfg := NewConfig(cfgPath)
	cfg.HomeDirFunc = func() (string, error) {
		t.Fatal("HomeDirFunc should not be called when ConfigFile is set")
		return "", nil
	}
	cfg.Stderr = &stderr

	if err := LoadConfig(cfg); err != nil {
		t.Fatalf("LoadConfig returned unexpected error: %v", err)
	}
	if cfg.ConfigFileUsed != cfgPath {
		t.Fatalf("expected ConfigFileUsed %q, got %q", cfgPath, cfg.ConfigFileUsed)
	}
	if got := cfg.Viper.GetString("vault"); got != "test" {
		t.Fatalf("expected viper key vault=%q, got %q", "test", got)
	}
	if !strings.Contains(stderr.String(), "Using config file:") {
		t.Fatalf("expected stderr notice, got %q", stderr.String())
	}
}

func TestLoadConfigFromHomeDirFile(t *testing.T) {
	homeDir := t.TempDir()
	cfgPath := filepath.Join(homeDir, ".pwd-manager.yaml")
	if err := os.WriteFile(cfgPath, []byte("profile: default\n"), 0o600); err != nil {
		t.Fatalf("write home config: %v", err)
	}

	var stderr bytes.Buffer
	cfg := NewConfig("")
	cfg.HomeDirFunc = func() (string, error) {
		return homeDir, nil
	}
	cfg.Stderr = &stderr

	if err := LoadConfig(cfg); err != nil {
		t.Fatalf("LoadConfig returned unexpected error: %v", err)
	}
	if cfg.ConfigFileUsed == "" {
		t.Fatal("expected ConfigFileUsed to be populated")
	}
	if got := cfg.Viper.GetString("profile"); got != "default" {
		t.Fatalf("expected viper key profile=%q, got %q", "default", got)
	}
	if !strings.Contains(stderr.String(), "Using config file:") {
		t.Fatalf("expected stderr notice, got %q", stderr.String())
	}
}

func TestLoadConfigBoundaries(t *testing.T) {
	if err := LoadConfig(nil); err == nil {
		t.Fatal("expected error when calling LoadConfig(nil), got nil")
	}

	emptyHome := t.TempDir()
	zeroCfg := &Config{
		HomeDirFunc: func() (string, error) {
			return emptyHome, nil
		},
	}
	if err := LoadConfig(zeroCfg); err != nil {
		t.Fatalf("expected zero-initialized Config with missing default file to succeed, got %v", err)
	}
	if zeroCfg.Viper == nil {
		t.Fatal("expected LoadConfig to initialize nil Viper instance")
	}
	if zeroCfg.Stderr == nil {
		t.Fatal("expected LoadConfig to initialize nil Stderr writer")
	}

	missingExplicit := NewConfig(filepath.Join(emptyHome, "does-not-exist.yaml"))
	if err := LoadConfig(missingExplicit); err == nil {
		t.Fatal("expected error when explicit ConfigFile does not exist, got nil")
	}
}

func TestLoadConfigStderrWriteError(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("vault: test\n"), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	wantErr := errors.New("broken pipe")
	cfg := NewConfig(cfgPath)
	cfg.Stderr = rootErrWriter{err: wantErr}

	err := LoadConfig(cfg)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped stderr write error %v, got %v", wantErr, err)
	}
}

func TestContextConfigHelpersBoundary(t *testing.T) {
	if cfg, ok := ConfigFromContext(nil); ok || cfg != nil {
		t.Fatalf("expected (nil, false) for nil context, got (%v, %v)", cfg, ok)
	}
	if cfg, ok := ConfigFromContext(context.Background()); ok || cfg != nil {
		t.Fatalf("expected (nil, false) for empty context, got (%v, %v)", cfg, ok)
	}

	want := NewConfig("custom.yaml")
	ctx := WithConfig(nil, want)
	got, ok := ConfigFromContext(ctx)
	if !ok || got != want {
		t.Fatalf("expected (%p, true) from WithConfig(nil, ...), got (%p, %v)", want, got, ok)
	}
}

func TestCommandRunnerReceivesInjectedConfig(t *testing.T) {
	injected := NewConfig("")
	injected.HomeDirFunc = func() (string, error) {
		return t.TempDir(), nil
	}
	if err := LoadConfig(injected); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	var received *Config
	cmd := &cobra.Command{
		Use:               "test",
		PersistentPreRunE: rootCmd.PersistentPreRunE,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, ok := ConfigFromContext(cmd.Context())
			if !ok {
				return errors.New("missing config in command context")
			}
			received = cfg
			return nil
		},
	}
	cmd.SetContext(WithConfig(context.Background(), injected))

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute: %v", err)
	}
	if received != injected {
		t.Fatalf("expected injected config pointer %p, got %p", injected, received)
	}
}

func TestPersistentPreRunELoadsAndPropagatesError(t *testing.T) {
	origCfgFile := cfgFile
	t.Cleanup(func() {
		cfgFile = origCfgFile
	})

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("key: val\n"), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfgFile = cfgPath

	var stderr bytes.Buffer
	var loaded *Config
	cmd := &cobra.Command{
		Use:               "test-load",
		SilenceErrors:     true,
		SilenceUsage:      true,
		PersistentPreRunE: rootCmd.PersistentPreRunE,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, ok := ConfigFromContext(cmd.Context())
			if !ok {
				return errors.New("expected config in context")
			}
			loaded = cfg
			return nil
		},
	}
	cmd.SetErr(&stderr)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute failed: %v", err)
	}
	if loaded == nil || loaded.ConfigFileUsed != cfgPath {
		t.Fatalf("expected loaded ConfigFileUsed %q, got %+v", cfgPath, loaded)
	}

	cfgFile = filepath.Join(tmpDir, "missing.yaml")
	failCmd := &cobra.Command{
		Use:               "test-fail",
		SilenceErrors:     true,
		SilenceUsage:      true,
		PersistentPreRunE: rootCmd.PersistentPreRunE,
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	if err := failCmd.Execute(); err == nil {
		t.Fatal("expected error from PersistentPreRunE when explicit config file is missing")
	}
}

func TestInitConfigDoesNotExitOnMissingHomeAndUpdatesContextOnSuccess(t *testing.T) {
	origCfgFile := cfgFile
	origHome := os.Getenv("HOME")
	origCtx := rootCmd.Context()
	t.Cleanup(func() {
		cfgFile = origCfgFile
		_ = os.Setenv("HOME", origHome)
		rootCmd.SetContext(origCtx)
		rootCmd.SetErr(nil)
	})

	cfgFile = ""
	_ = os.Unsetenv("HOME")

	var stderr bytes.Buffer
	rootCmd.SetErr(&stderr)

	initConfig()
	if !strings.Contains(stderr.String(), "resolve home directory") {
		t.Fatalf("expected missing home error on stderr, got %q", stderr.String())
	}

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: test\n"), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfgFile = cfgPath
	stderr.Reset()

	initConfig()
	cfg, ok := ConfigFromContext(rootCmd.Context())
	if !ok || cfg == nil {
		t.Fatal("expected initConfig to store Config in rootCmd context")
	}
	if cfg.ConfigFileUsed != cfgPath {
		t.Fatalf("expected ConfigFileUsed %q, got %q", cfgPath, cfg.ConfigFileUsed)
	}
}
