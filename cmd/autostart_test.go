package cmd

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeAutostart replaces the OS hooks of the autostart command and records
// the launchctl calls; failures maps a launchctl subcommand to its error.
func fakeAutostart(t *testing.T, failures map[string]error) (agentsDir string, calls *[][]string) {
	t.Helper()
	oldGOOS, oldDir, oldExe, oldRun, oldCfg := autostartGOOS, launchAgentsDir, autostartExecutable, runLaunchctl, cfgFile
	t.Cleanup(func() {
		autostartGOOS, launchAgentsDir, autostartExecutable, runLaunchctl, cfgFile = oldGOOS, oldDir, oldExe, oldRun, oldCfg
	})
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	agentsDir = filepath.Join(home, "Library", "LaunchAgents")
	autostartGOOS, cfgFile = "darwin", ""
	launchAgentsDir = func() (string, error) { return agentsDir, nil }
	autostartExecutable = func() (string, error) { return "/opt/pwd & co/pwd-manager", nil }
	calls = &[][]string{}
	runLaunchctl = func(_ context.Context, args ...string) error {
		*calls = append(*calls, args)
		return failures[args[0]]
	}
	return agentsDir, calls
}

// launchctlExitError returns a real launchctl-style exit status.
func launchctlExitError(t *testing.T, code string) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+code).Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("exit %s: got %v, want *exec.ExitError", code, err)
	}
	return err
}

func runAutostart(t *testing.T, cmdName string) (string, error) {
	t.Helper()
	cmd := autostartEnableCmd
	if cmdName == "disable" {
		cmd = autostartDisableCmd
	}
	var out bytes.Buffer
	cmd.SetOut(&out)
	t.Cleanup(func() { cmd.SetOut(nil) })
	cmd.SetContext(context.Background())
	err := cmd.RunE(cmd, nil)
	return out.String(), err
}

func TestAutostartEnableWritesAndReloadsLaunchAgent(t *testing.T) {
	agentsDir, calls := fakeAutostart(t, map[string]error{"bootout": launchctlExitError(t, "3")})
	out, err := runAutostart(t, "enable")
	if err != nil {
		t.Fatal(err)
	}
	plistPath := filepath.Join(agentsDir, launchAgentLabel+".plist")
	if !strings.Contains(out, plistPath) {
		t.Errorf("notice = %q, want plist path", out)
	}
	domain := launchDomain()
	want := [][]string{{"bootout", domain + "/" + launchAgentLabel}, {"bootstrap", domain, plistPath}}
	if !reflect.DeepEqual(*calls, want) {
		t.Errorf("launchctl calls = %q, want %q", *calls, want)
	}
	data, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatal(err)
	}
	pidPath, err := daemonPidfilePath()
	if err != nil {
		t.Fatal(err)
	}
	strs := plistStrings(t, data)
	wantStrs := []string{launchAgentLabel, "/opt/pwd & co/pwd-manager", "daemon", "--restart", "Interactive", daemonLogPath(pidPath), daemonLogPath(pidPath)}
	if !reflect.DeepEqual(strs, wantStrs) {
		t.Errorf("plist strings = %q, want %q", strs, wantStrs)
	}
	for _, key := range []string{"<key>RunAtLoad</key>\n\t<true/>", "<key>SuccessfulExit</key>\n\t\t<false/>"} {
		if !strings.Contains(string(data), key) {
			t.Errorf("plist lacks %q:\n%s", key, data)
		}
	}
	if _, err := os.Stat(filepath.Dir(pidPath)); err != nil {
		t.Errorf("daemon log dir not created: %v", err)
	}
	if plutil, err := exec.LookPath("plutil"); err == nil {
		if out, err := exec.Command(plutil, "-lint", plistPath).CombinedOutput(); err != nil {
			t.Errorf("plutil rejects the plist: %v\n%s", err, out)
		}
	}
}

// plistStrings checks data is well-formed XML and returns its decoded
// <string> values in order.
func plistStrings(t *testing.T, data []byte) []string {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	var strs []string
	inString := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return strs
		}
		if err != nil {
			t.Fatalf("plist is not well-formed: %v\n%s", err, data)
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			inString = tok.Name.Local == "string"
		case xml.EndElement:
			inString = false
		case xml.CharData:
			if inString {
				strs = append(strs, string(tok))
			}
		}
	}
}

func TestAutostartEnableUsesAbsoluteConfigPath(t *testing.T) {
	agentsDir, _ := fakeAutostart(t, nil)
	cfgFile = "relative.yaml"
	if _, err := runAutostart(t, "enable"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(agentsDir, launchAgentLabel+".plist"))
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs("relative.yaml")
	if err != nil {
		t.Fatal(err)
	}
	strs := plistStrings(t, data)
	if !reflect.DeepEqual(strs[2:6], []string{"daemon", "--restart", "--config", abs}) {
		t.Errorf("daemon args = %q, want absolute --config %q", strs[2:6], abs)
	}
}

func TestAutostartEnableReportsUnloadFailureWithoutLoading(t *testing.T) {
	_, calls := fakeAutostart(t, map[string]error{"bootout": launchctlExitError(t, "5")})
	_, err := runAutostart(t, "enable")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || !strings.Contains(err.Error(), "unload") {
		t.Fatalf("err = %v, want wrapped unload exit error", err)
	}
	if len(*calls) != 1 {
		t.Errorf("launchctl calls = %q, want only bootout", *calls)
	}
}

func TestAutostartEnableReportsLoadFailure(t *testing.T) {
	loadErr := errors.New("bootstrap failed")
	fakeAutostart(t, map[string]error{"bootstrap": loadErr})
	if _, err := runAutostart(t, "enable"); !errors.Is(err, loadErr) {
		t.Fatalf("err = %v, want wrapped %v", err, loadErr)
	}
}

func TestAutostartDisableUnloadsAndRemovesPlist(t *testing.T) {
	agentsDir, calls := fakeAutostart(t, nil)
	plistPath := filepath.Join(agentsDir, launchAgentLabel+".plist")
	if err := os.MkdirAll(agentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plistPath, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runAutostart(t, "disable"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plistPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plist still present: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0][0] != "bootout" {
		t.Errorf("launchctl calls = %q, want one bootout", *calls)
	}
}

func TestAutostartDisableWhenNothingInstalled(t *testing.T) {
	fakeAutostart(t, map[string]error{"bootout": launchctlExitError(t, "3")})
	out, err := runAutostart(t, "disable")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "disabled") {
		t.Errorf("notice = %q", out)
	}
}

func TestAutostartRejectsOtherPlatformsBeforeSideEffects(t *testing.T) {
	agentsDir, calls := fakeAutostart(t, nil)
	autostartGOOS = "linux"
	for _, name := range []string{"enable", "disable"} {
		if _, err := runAutostart(t, name); err == nil || !strings.Contains(err.Error(), "only supported on macOS") {
			t.Errorf("%s: err = %v, want unsupported platform", name, err)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("launchctl calls = %q, want none", *calls)
	}
	if _, err := os.Stat(agentsDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LaunchAgents dir created: %v", err)
	}
}
