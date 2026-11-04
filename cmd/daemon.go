package cmd

import (
	"fmt"

	"github.com/nanaki-93/pwd-manager/internal/daemon"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start background service for hotkey password access",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := startDaemon(); err != nil {
			return fmt.Errorf("start daemon: %w", err)
		}
		return nil
	},
}

// startDaemon starts the hotkey daemon; tests replace it with a fake.
var startDaemon = daemon.Start

func init() {
	rootCmd.AddCommand(daemonCmd)
}
