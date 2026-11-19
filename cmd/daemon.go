package cmd

import (
	"context"
	"fmt"

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
		"The daemon records its pid in the user cache dir; --restart stops the daemon recorded there first.",
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
	rootCmd.AddCommand(daemonCmd)
}
