package cmd

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

// launchAgentLabel names the LaunchAgent that starts the daemon at login.
const launchAgentLabel = "io.github.nanaki-93.pwd-manager.daemon"

// autostartGOOS is the platform autostart runs on; tests replace it.
var autostartGOOS = runtime.GOOS

// autostartExecutable returns the absolute path of the binary the
// LaunchAgent runs; tests replace it.
var autostartExecutable = resolvedExecutable

var autostartCmd = &cobra.Command{
	Use:   "autostart",
	Short: "start the daemon automatically when you log in (macOS)",
	Long: "Start the hotkey daemon automatically when you log in.\n\n" +
		"`autostart enable` writes a LaunchAgent to ~/Library/LaunchAgents/" + launchAgentLabel + ".plist " +
		"that runs `pwd-manager daemon --restart` at login, writing its output to daemon.log in the user cache dir. " +
		"It does not start the daemon now; run `pwd-manager daemon --detach` for that. " +
		"`autostart disable` removes the LaunchAgent; a running daemon keeps running.",
}

var autostartEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "start the daemon at login",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := enableAutostart()
		if err != nil {
			return err
		}
		return printAutostartNotice(cmd.OutOrStdout(), "Daemon will start at login (LaunchAgent %s)\n", path)
	},
}

var autostartDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "stop starting the daemon at login",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := disableAutostart()
		if err != nil {
			return err
		}
		return printAutostartNotice(cmd.OutOrStdout(), "Daemon will no longer start at login (removed %s)\n", path)
	},
}

func printAutostartNotice(out io.Writer, format, path string) error {
	if _, err := fmt.Fprintf(out, format, path); err != nil {
		return fmt.Errorf("write autostart notice: %w", err)
	}
	return nil
}

// enableAutostart writes the daemon LaunchAgent and returns its path.
func enableAutostart() (string, error) {
	path, err := launchAgentPath()
	if err != nil {
		return "", err
	}
	exe, err := autostartExecutable()
	if err != nil {
		return "", fmt.Errorf("enable autostart: %w", err)
	}
	pidPath, err := daemonPidfilePath()
	if err != nil {
		return "", fmt.Errorf("enable autostart: locate daemon pidfile: %w", err)
	}
	logPath := daemonLogPath(pidPath)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return "", fmt.Errorf("enable autostart: create daemon log dir: %w", err)
	}
	args, err := autostartDaemonArgs()
	if err != nil {
		return "", err
	}
	plist := launchAgentPlist(exe, args, logPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("enable autostart: create LaunchAgents dir: %w", err)
	}
	if err := os.WriteFile(path, plist, 0o644); err != nil {
		return "", fmt.Errorf("enable autostart: write %s: %w", path, err)
	}
	return path, nil
}

// autostartDaemonArgs returns `daemon --restart`, plus --config with an
// absolute path when one was given, since launchd runs it from /.
func autostartDaemonArgs() ([]string, error) {
	args := []string{"daemon", "--restart"}
	if cfgFile == "" {
		return args, nil
	}
	abs, err := filepath.Abs(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("enable autostart: resolve config path %s: %w", cfgFile, err)
	}
	return append(args, "--config", abs), nil
}

// disableAutostart removes the daemon LaunchAgent, if present, and returns
// its path.
func disableAutostart() (string, error) {
	path, err := launchAgentPath()
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("disable autostart: remove %s: %w", path, err)
	}
	return path, nil
}

// launchAgentPath returns where the daemon LaunchAgent lives. Only macOS has
// LaunchAgents, so other platforms get an error.
func launchAgentPath() (string, error) {
	if autostartGOOS != "darwin" {
		return "", fmt.Errorf("autostart is not supported on %s", autostartGOOS)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist"), nil
}

// launchAgentPlist renders a LaunchAgent that runs exe with args once per
// login, in the GUI session the hotkey and window need, appending its output
// to logPath. It is not kept alive, so `daemon --restart` can replace it.
func launchAgentPlist(exe string, args []string, logPath string) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
`)
	plistString(&b, "Label", launchAgentLabel)
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, arg := range append([]string{exe}, args...) {
		b.WriteString("\t\t<string>" + xmlEscape(arg) + "</string>\n")
	}
	b.WriteString("\t</array>\n")
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	plistString(&b, "LimitLoadToSessionType", "Aqua")
	plistString(&b, "ProcessType", "Interactive")
	plistString(&b, "StandardOutPath", logPath)
	plistString(&b, "StandardErrorPath", logPath)
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes()
}

func plistString(b *bytes.Buffer, key, value string) {
	b.WriteString("\t<key>" + xmlEscape(key) + "</key>\n\t<string>" + xmlEscape(value) + "</string>\n")
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	// EscapeText only fails when the writer does; bytes.Buffer never does.
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// resolvedExecutable returns the running binary's absolute path with
// symlinks resolved, so the LaunchAgent keeps working from any shell.
func resolvedExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve executable %s: %w", exe, err)
	}
	return resolved, nil
}

func init() {
	autostartCmd.AddCommand(autostartEnableCmd, autostartDisableCmd)
	rootCmd.AddCommand(autostartCmd)
}
