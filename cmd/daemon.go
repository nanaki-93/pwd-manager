package cmd

import (
	"github.com/nanaki-93/pwd-manager/internal/daemon"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start background service for hotkey password access",
	Run: func(cmd *cobra.Command, args []string) {
		daemon.Start()
	},
}

func init() {
	rootCmd.AddCommand(daemonCmd)
}
