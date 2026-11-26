package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useDarwinAutostart makes autostart behave as on macOS with exe as the
// running binary and a fresh HOME, and returns the LaunchAgent path.
func useDarwinAutostart(t *testing.T, exe string) string {
	t.Helper()
	oldGOOS, oldExe, oldConfig := autostartGOOS, autostartExecutable, cfgFile
	t.Cleanup(func() {
		autostartGOOS, autostartExecutable, cfgFile = oldGOOS, oldExe, oldConfig
		autostartEnableCmd.SetOut(nil)
		autostartDisableCmd.SetOut(nil)
	})
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	autostartGOOS, cfgFile = "darwin", ""
	autostartEnableCmd.SetOut(io.Discard)
	autostartDisableCmd.SetOut(io.Discard)
	autostartExecutable = func() (string, error) { return exe, nil }
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
}

func TestAutostartEnableWritesLaunchAgent(t *testing.T) {
	path := useDarwinAutostart(t, "/opt/pwd & manager/pwd-manager")
	cfgFile = "conf.yaml"
	var out bytes.Buffer
	autostartEnableCmd.SetOut(&out)
	if err := autostartEnableCmd.RunE(autostartEnableCmd, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pidPath, err := daemonPidfilePath()
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	plist := string(data)
	for _, want := range []string{
		"<string>" + launchAgentLabel + "</string>",
		"<string>/opt/pwd &amp; manager/pwd-manager</string>\n\t\t<string>daemon</string>\n\t\t<string>--restart</string>\n" +
			"\t\t<string>--config</string>\n\t\t<string>" + filepath.Join(cwd, "conf.yaml") + "</string>\n",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<string>Aqua</string>",
		"<string>" + daemonLogPath(pidPath) + "</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %q:\n%s", want, plist)
		}
	}
	if strings.Contains(plist, "KeepAlive") {
		t.Error("plist keeps the daemon alive, so `daemon --restart` could not replace it")
	}
	if !strings.Contains(out.String(), path) {
		t.Errorf("notice = %q", out.String())
	}
	if _, err := os.Stat(filepath.Dir(daemonLogPath(pidPath))); err != nil {
		t.Errorf("log dir not created: %v", err)
	}
}

func TestAutostartDisableRemovesLaunchAgentAndIsIdempotent(t *testing.T) {
	path := useDarwinAutostart(t, "/bin/pwd-manager")
	if err := autostartEnableCmd.RunE(autostartEnableCmd, nil); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := autostartDisableCmd.RunE(autostartDisableCmd, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("LaunchAgent still present: %v", err)
		}
	}
}

func TestAutostartUnsupportedOutsideMacOS(t *testing.T) {
	useDarwinAutostart(t, "/bin/pwd-manager")
	autostartGOOS = "linux"
	for name, run := range map[string]func() (string, error){"enable": enableAutostart, "disable": disableAutostart} {
		if _, err := run(); err == nil || !strings.Contains(err.Error(), "not supported on linux") {
			t.Errorf("%s error = %v", name, err)
		}
	}
}

func TestAutostartEnableSurfacesExecutableError(t *testing.T) {
	path := useDarwinAutostart(t, "")
	exeErr := errors.New("no executable")
	autostartExecutable = func() (string, error) { return "", exeErr }
	if _, err := enableAutostart(); !errors.Is(err, exeErr) {
		t.Fatalf("error = %v, want wrapping %v", err, exeErr)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LaunchAgent written despite error: %v", err)
	}
}

func TestAutostartEnableSurfacesWriteError(t *testing.T) {
	path := useDarwinAutostart(t, "/bin/pwd-manager")
	// A file where the LaunchAgents directory belongs makes creating it fail.
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(path)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Dir(path), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := enableAutostart(); err == nil || !strings.Contains(err.Error(), "LaunchAgents dir") {
		t.Fatalf("error = %v", err)
	}
}
