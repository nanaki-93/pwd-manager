package cmd

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// launchAgentLabel identifies the login item to launchd. It matches the
// label of earlier hand-written plists, so enabling replaces them.
const launchAgentLabel = "com.github.nanaki.pwd-manager"

// launchctlNotLoadedExit is the launchctl exit status ("No such process")
// of bootout for a service that is not loaded.
const launchctlNotLoadedExit = 3

var autostartCmd = &cobra.Command{
	Use:   "autostart",
	Short: "start the daemon automatically at login (macOS)",
	Long: "Start the daemon automatically at login (macOS).\n\n" +
		"`autostart enable` writes the LaunchAgent ~/Library/LaunchAgents/" + launchAgentLabel + ".plist, " +
		"which runs `daemon --restart` from this binary's current path at every login and restarts it if it crashes, " +
		"then loads it, which starts the daemon now. Run it again after moving the binary. " +
		"`autostart disable` unloads and removes the LaunchAgent, which stops a daemon it started.",
}

var autostartEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "start the daemon at login from this binary",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, err := autostartContext(cmd)
		if err != nil {
			return err
		}
		path, err := enableAutostart(ctx)
		if err != nil {
			return err
		}
		return writeNotice(cmd.OutOrStdout(), "Daemon autostart enabled: %s\n", path)
	},
}

var autostartDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "stop starting the daemon at login",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, err := autostartContext(cmd)
		if err != nil {
			return err
		}
		if err := disableAutostart(ctx); err != nil {
			return err
		}
		return writeNotice(cmd.OutOrStdout(), "Daemon autostart disabled\n")
	},
}

// autostartGOOS, launchAgentsDir, autostartExecutable and runLaunchctl are
// replaced by tests to avoid touching the real login items.
var (
	autostartGOOS       = runtime.GOOS
	launchAgentsDir     = defaultLaunchAgentsDir
	autostartExecutable = resolvedExecutable
	runLaunchctl        = execLaunchctl
)

// autostartContext checks the platform before any side effect and returns
// the command context.
func autostartContext(cmd *cobra.Command) (context.Context, error) {
	if autostartGOOS != "darwin" {
		return nil, fmt.Errorf("autostart is only supported on macOS, not %s", autostartGOOS)
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx, nil
}

// enableAutostart writes the LaunchAgent for this executable and reloads it,
// so a stale agent loaded from an older plist is replaced. It returns the
// plist path.
func enableAutostart(ctx context.Context) (string, error) {
	exe, err := autostartExecutable()
	if err != nil {
		return "", fmt.Errorf("enable autostart: %w", err)
	}
	pidPath, err := daemonPidfilePath()
	if err != nil {
		return "", fmt.Errorf("enable autostart: locate daemon pidfile: %w", err)
	}
	dir, err := launchAgentsDir()
	if err != nil {
		return "", fmt.Errorf("enable autostart: %w", err)
	}
	plistPath := filepath.Join(dir, launchAgentLabel+".plist")
	args, err := autostartDaemonArgs()
	if err != nil {
		return "", fmt.Errorf("enable autostart: %w", err)
	}
	plist, err := launchAgentPlist(exe, args, daemonLogPath(pidPath))
	if err != nil {
		return "", fmt.Errorf("enable autostart: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("enable autostart: create %s: %w", dir, err)
	}
	if err := os.MkdirAll(filepath.Dir(pidPath), 0o700); err != nil {
		return "", fmt.Errorf("enable autostart: create daemon log dir: %w", err)
	}
	if err := os.WriteFile(plistPath, plist, 0o644); err != nil {
		return "", fmt.Errorf("enable autostart: write %s: %w", plistPath, err)
	}
	if err := bootoutLaunchAgent(ctx); err != nil {
		return "", fmt.Errorf("enable autostart: %w", err)
	}
	if err := runLaunchctl(ctx, "bootstrap", launchDomain(), plistPath); err != nil {
		return "", fmt.Errorf("enable autostart: load %s: %w", plistPath, err)
	}
	return plistPath, nil
}

// disableAutostart unloads the LaunchAgent and removes its plist; either may
// already be gone.
func disableAutostart(ctx context.Context) error {
	dir, err := launchAgentsDir()
	if err != nil {
		return fmt.Errorf("disable autostart: %w", err)
	}
	if err := bootoutLaunchAgent(ctx); err != nil {
		return fmt.Errorf("disable autostart: %w", err)
	}
	plistPath := filepath.Join(dir, launchAgentLabel+".plist")
	if err := os.Remove(plistPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("disable autostart: remove %s: %w", plistPath, err)
	}
	return nil
}

// autostartDaemonArgs returns the daemon arguments launchd runs: --restart
// stops a daemon started by hand, and --config keeps this process's config
// as an absolute path, since launchd runs the daemon from /.
func autostartDaemonArgs() ([]string, error) {
	args := []string{"daemon", "--restart"}
	if cfgFile == "" {
		return args, nil
	}
	cfg, err := filepath.Abs(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("resolve config path %s: %w", cfgFile, err)
	}
	return append(args, "--config", cfg), nil
}

// launchAgentPlist renders a LaunchAgent that runs exe with args at login,
// restarts it only after a failed exit (a stopped daemon exits cleanly and
// stays stopped) and appends its output to logPath.
func launchAgentPlist(exe string, args []string, logPath string) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchAgentLabel + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, arg := range append([]string{exe}, args...) {
		if err := writePlistString(&b, "\t\t", arg); err != nil {
			return nil, err
		}
	}
	b.WriteString(`	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardOutPath</key>
`)
	if err := writePlistString(&b, "\t", logPath); err != nil {
		return nil, err
	}
	b.WriteString("\t<key>StandardErrorPath</key>\n")
	if err := writePlistString(&b, "\t", logPath); err != nil {
		return nil, err
	}
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes(), nil
}

// writePlistString writes value as an XML-escaped plist string element.
func writePlistString(b *bytes.Buffer, indent, value string) error {
	b.WriteString(indent + "<string>")
	if err := xml.EscapeText(b, []byte(value)); err != nil {
		return fmt.Errorf("encode plist string %q: %w", value, err)
	}
	b.WriteString("</string>\n")
	return nil
}

// bootoutLaunchAgent unloads the LaunchAgent, which stops a daemon it runs.
// An agent that is not loaded is left alone.
func bootoutLaunchAgent(ctx context.Context) error {
	err := runLaunchctl(ctx, "bootout", launchDomain()+"/"+launchAgentLabel)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == launchctlNotLoadedExit {
		return nil
	}
	if err != nil {
		return fmt.Errorf("unload %s: %w", launchAgentLabel, err)
	}
	return nil
}

// launchDomain is the launchd domain of the logged-in user's GUI session,
// where agents can open windows and register hotkeys.
func launchDomain() string {
	return "gui/" + strconv.Itoa(os.Getuid())
}

// execLaunchctl runs launchctl with args, including its output in the error.
func execLaunchctl(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func defaultLaunchAgentsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents"), nil
}

// resolvedExecutable returns the absolute path of the running binary with
// symlinks resolved, so the LaunchAgent does not depend on the shell's PATH.
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

// writeNotice writes a formatted confirmation to out.
func writeNotice(out io.Writer, format string, args ...any) error {
	if _, err := fmt.Fprintf(out, format, args...); err != nil {
		return fmt.Errorf("write autostart notice: %w", err)
	}
	return nil
}

func init() {
	autostartCmd.AddCommand(autostartEnableCmd, autostartDisableCmd)
	rootCmd.AddCommand(autostartCmd)
}
