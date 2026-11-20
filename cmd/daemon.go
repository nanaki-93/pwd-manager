package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/nanaki-93/pwd-manager/internal/daemon"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start background service for hotkey password access",
	Long: "Start background service for hotkey password access.\n\n" +
		"Ctrl+Shift+P opens the password window: unlock it with Touch ID or the master password, " +
		"then copy, edit, add or delete passwords. Closing or locking the window locks the store again; " +
		"copied passwords are cleared from the clipboard automatically.\n\n" +
		"The daemon records its pid in the user cache dir; --restart stops the daemon recorded there first. " +
		"--detach starts it in the background, detached from the terminal, writing its output to daemon.log " +
		"next to the pidfile.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			// Context is nil only when RunE is invoked outside Execute.
			ctx = context.Background()
		}
		pidPath, err := daemonPidfilePath()
		if err != nil {
			return fmt.Errorf("locate daemon pidfile: %w", err)
		}
		if detachDaemon {
			return startDetachedDaemon(cmd.OutOrStdout(), pidPath)
		}
		if restartDaemon {
			if err := stopPreviousDaemon(ctx, pidPath); err != nil {
				return err
			}
		}
		return runWithPidfile(ctx, pidPath, startDaemon)
	},
}

// startDaemon starts the hotkey daemon; tests replace it with a fake.
var startDaemon = daemon.Start

// restartDaemon is set by --restart.
var restartDaemon bool

// detachDaemon is set by --detach.
var detachDaemon bool

// spawnDetached starts this executable with args in the background, writing
// its output to logPath, and returns its pid; tests replace it with a fake.
var spawnDetached = startDetachedProcess

// startDetachedDaemon re-runs `daemon` in a new background session, without
// --detach so the child runs the daemon itself, and reports the child's pid
// and log file on out. The child stops the previous daemon when --restart
// was given and records its own pid in the pidfile.
func startDetachedDaemon(out io.Writer, pidPath string) error {
	logPath := daemonLogPath(pidPath)
	pid, err := spawnDetached(detachedDaemonArgs(), logPath)
	if err != nil {
		return fmt.Errorf("start detached daemon: %w", err)
	}
	if _, err := fmt.Fprintf(out, "Daemon started in the background (pid %d), logging to %s\n", pid, logPath); err != nil {
		return fmt.Errorf("write detached daemon notice: %w", err)
	}
	return nil
}

// detachedDaemonArgs returns the arguments of the detached child: `daemon`
// plus the --restart and --config flags this process was given.
func detachedDaemonArgs() []string {
	args := []string{"daemon"}
	if restartDaemon {
		args = append(args, "--restart")
	}
	if cfgFile != "" {
		args = append(args, "--config", cfgFile)
	}
	return args
}

// stopPreviousDaemon stops the daemon recorded at pidPath, if it runs the
// same executable as this process.
func stopPreviousDaemon(ctx context.Context, pidPath string) error {
	name, err := executableName()
	if err != nil {
		return fmt.Errorf("stop running daemon: %w", err)
	}
	if err := stopRecordedDaemon(ctx, pidPath, name, daemonStopTimeout); err != nil {
		return fmt.Errorf("stop running daemon: %w", err)
	}
	return nil
}

func init() {
	daemonCmd.Flags().BoolVar(&restartDaemon, "restart", false, "stop the running daemon before starting")
	daemonCmd.Flags().BoolVar(&detachDaemon, "detach", false, "run the daemon in the background, detached from the terminal")
	rootCmd.AddCommand(daemonCmd)
}
