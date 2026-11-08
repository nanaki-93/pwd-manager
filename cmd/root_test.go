package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
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

// writeRootTestConfig writes content to dir/name with owner-only permissions and returns its path.
func writeRootTestConfig(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config %s: %v", path, err)
	}
	return path
}

// homeDirIn returns a HomeDirFunc that reports dir.
func homeDirIn(dir string) func() (string, error) {
	return func() (string, error) { return dir, nil }
}

func TestLoadConfigReadsConfigFile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		file     string
		key      string
		value    string
		explicit bool
	}{
		{"explicit file", "config.yaml", "vault", "test", true},
		{"default file in home", ".pwd-manager.yaml", "profile", "default", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := writeRootTestConfig(t, home, tc.file, tc.key+": "+tc.value+"\n")
			var stderr bytes.Buffer
			cfg := NewConfig("")
			cfg.HomeDirFunc = homeDirIn(home)
			if tc.explicit {
				cfg.ConfigFile = path
				cfg.HomeDirFunc = func() (string, error) {
					t.Fatal("HomeDirFunc should not be called when ConfigFile is set")
					return "", nil
				}
			}
			cfg.Stderr = &stderr

			if err := LoadConfig(cfg); err != nil {
				t.Fatalf("LoadConfig returned unexpected error: %v", err)
			}
			if cfg.ConfigFileUsed != path {
				t.Fatalf("expected ConfigFileUsed %q, got %q", path, cfg.ConfigFileUsed)
			}
			if got := cfg.Viper.GetString(tc.key); got != tc.value {
				t.Fatalf("expected viper key %s=%q, got %q", tc.key, tc.value, got)
			}
			if !strings.Contains(stderr.String(), "Using config file:") {
				t.Fatalf("expected stderr notice, got %q", stderr.String())
			}
		})
	}
}

func TestLoadConfigErrors(t *testing.T) {
	homeErr := errors.New("home directory unavailable")
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, dir string) *Config
		wantIs  error
		wantMsg string
		wrapped bool
	}{
		{
			name:    "nil config",
			setup:   func(*testing.T, string) *Config { return nil },
			wantMsg: "nil config",
		},
		{
			name: "home directory lookup fails",
			setup: func(*testing.T, string) *Config {
				cfg := NewConfig("")
				cfg.HomeDirFunc = func() (string, error) { return "", homeErr }
				return cfg
			},
			wantIs: homeErr,
		},
		{
			name: "malformed default file",
			setup: func(t *testing.T, dir string) *Config {
				writeRootTestConfig(t, dir, ".pwd-manager.yaml", ":\tinvalid: [yaml\n")
				cfg := NewConfig("")
				cfg.HomeDirFunc = homeDirIn(dir)
				return cfg
			},
			wantMsg: "read default config",
			wrapped: true,
		},
		{
			name: "missing explicit file",
			setup: func(_ *testing.T, dir string) *Config {
				return NewConfig(filepath.Join(dir, "does-not-exist.yaml"))
			},
			wantMsg: "does-not-exist.yaml",
			wrapped: true,
		},
		{
			name: "malformed explicit file",
			setup: func(t *testing.T, dir string) *Config {
				return NewConfig(writeRootTestConfig(t, dir, "malformed.yaml", ":\tbad: [yaml\n"))
			},
			wrapped: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.setup(t, t.TempDir())
			var stderr bytes.Buffer
			if cfg != nil {
				cfg.Stderr = &stderr
			}
			err := LoadConfig(cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("expected wrapped error %v, got %v", tc.wantIs, err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("expected %q in error, got %v", tc.wantMsg, err)
			}
			if tc.wrapped && errors.Unwrap(err) == nil {
				t.Fatalf("expected wrapped underlying error, got %v", err)
			}
			if cfg != nil && (cfg.ConfigFileUsed != "" || stderr.Len() != 0) {
				t.Fatalf("failed load published as loaded: notice=%q path=%q", stderr.String(), cfg.ConfigFileUsed)
			}
		})
	}
}

func TestLoadConfigFillsZeroConfigDefaults(t *testing.T) {
	zeroCfg := &Config{HomeDirFunc: homeDirIn(t.TempDir())}
	if err := LoadConfig(zeroCfg); err != nil {
		t.Fatalf("expected zero-initialized Config with missing default file to succeed, got %v", err)
	}
	if zeroCfg.Viper == nil {
		t.Fatal("expected LoadConfig to initialize nil Viper instance")
	}
	if zeroCfg.Stderr == nil {
		t.Fatal("expected LoadConfig to initialize nil Stderr writer")
	}
}

func TestLoadConfigStderrWriteError(t *testing.T) {
	wantErr := errors.New("broken pipe")
	cfg := NewConfig(writeRootTestConfig(t, t.TempDir(), "config.yaml", "vault: test\n"))
	cfg.Stderr = rootErrWriter{err: wantErr}

	if err := LoadConfig(cfg); !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped stderr write error %v, got %v", wantErr, err)
	}
}

func TestLoadConfigNilHomeDirFuncUsesPortableLookup(t *testing.T) {
	previous := userHomeDir
	t.Cleanup(func() { userHomeDir = previous })
	wantErr := errors.New("portable home lookup failed")
	calls := 0
	userHomeDir = func() (string, error) {
		calls++
		return "", wantErr
	}
	cfg := &Config{}
	if err := LoadConfig(cfg); !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped lookup error %v, got %v", wantErr, err)
	}
	if calls != 1 {
		t.Fatalf("expected one home lookup, got %d", calls)
	}
}

func TestLoadConfigEnvironmentOverrides(t *testing.T) {
	for _, tc := range []struct {
		name     string
		env      map[string]string
		withFile bool
		want     map[string]string
	}{
		{"unprefixed env ignored", map[string]string{"VAULT": "attacker"}, true, map[string]string{"vault": "test"}},
		{"prefixed env overrides file", map[string]string{"PWD_MANAGER_VAULT": "override"}, true, map[string]string{"vault": "override"}},
		{
			"unlisted prefixed key ignored",
			map[string]string{"PWD_MANAGER_UNLISTED_REGRESSION_KEY": "unexpected"}, true,
			map[string]string{"unlisted_regression_key": ""},
		},
		{
			"without default file",
			map[string]string{
				"VAULT":                             "unprefixed-vault",
				"PROFILE":                           "unprefixed-profile",
				"PWD_MANAGER_VAULT":                 "namespaced-vault",
				"PWD_MANAGER_PROFILE":               "namespaced-profile",
				"PWD_MANAGER_UNLISTED_BOUNDARY_KEY": "unexpected",
			},
			false,
			map[string]string{"vault": "namespaced-vault", "profile": "namespaced-profile", "unlisted_boundary_key": ""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			home := t.TempDir()
			cfg := NewConfig("")
			cfg.HomeDirFunc = homeDirIn(home)
			cfg.Stderr = io.Discard
			if tc.withFile {
				cfg.ConfigFile = writeRootTestConfig(t, home, "config.yaml", "vault: test\n")
			}
			if err := LoadConfig(cfg); err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			for key, want := range tc.want {
				if got := cfg.Viper.GetString(key); got != want {
					t.Errorf("config %q = %q, want %q", key, got, want)
				}
			}
			if !tc.withFile && cfg.ConfigFileUsed != "" {
				t.Fatalf("missing default file reported as loaded: %q", cfg.ConfigFileUsed)
			}
		})
	}
}

func TestConfigFromContext(t *testing.T) {
	stored := NewConfig("custom.yaml")
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want *Config
	}{
		{"nil context", nil, nil},
		{"context without config", context.Background(), nil},
		{"nil config stored", WithConfig(context.Background(), nil), nil},
		{"WithConfig on nil parent", WithConfig(nil, stored), stored},
		{"WithConfig on background", WithConfig(context.Background(), stored), stored},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ConfigFromContext(tc.ctx)
			if got != tc.want || ok != (tc.want != nil) {
				t.Fatalf("ConfigFromContext = (%p, %v), want (%p, %v)", got, ok, tc.want, tc.want != nil)
			}
		})
	}
}

// runRootPreRun executes a command using rootCmd's PersistentPreRunE and returns the config it saw.
func runRootPreRun(ctx context.Context) (*Config, error) {
	var seen *Config
	cmd := &cobra.Command{
		Use:               "test",
		SilenceErrors:     true,
		SilenceUsage:      true,
		PersistentPreRunE: rootCmd.PersistentPreRunE,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, ok := ConfigFromContext(cmd.Context())
			if !ok {
				return errors.New("missing config in command context")
			}
			seen = cfg
			return nil
		},
	}
	cmd.SetErr(io.Discard)
	if ctx != nil {
		cmd.SetContext(ctx)
	}
	err := cmd.Execute()
	return seen, err
}

func TestRootPersistentPreRunE(t *testing.T) {
	origCfgFile := cfgFile
	t.Cleanup(func() { cfgFile = origCfgFile })
	dir := t.TempDir()
	path := writeRootTestConfig(t, dir, "config.yaml", "key: val\n")
	missing := filepath.Join(dir, "missing.yaml")
	injected := NewConfig("")

	for _, tc := range []struct {
		name     string
		cfgFile  string
		injected *Config
		wantUsed string
		wantErr  bool
	}{
		{name: "injected config is kept", cfgFile: missing, injected: injected},
		{name: "loads --config file", cfgFile: path, wantUsed: path},
		{name: "missing --config file fails", cfgFile: missing, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgFile = tc.cfgFile
			var ctx context.Context
			if tc.injected != nil {
				ctx = WithConfig(context.Background(), tc.injected)
			}
			got, err := runRootPreRun(ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error from PersistentPreRunE, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("cmd.Execute: %v", err)
			}
			if tc.injected != nil && got != tc.injected {
				t.Fatalf("expected injected config %p, got %p", tc.injected, got)
			}
			if got.ConfigFileUsed != tc.wantUsed {
				t.Fatalf("expected ConfigFileUsed %q, got %q", tc.wantUsed, got.ConfigFileUsed)
			}
		})
	}
}
