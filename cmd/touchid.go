package cmd

import (
	"fmt"

	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
)

// touchidCmd groups the Touch ID opt-in and opt-out subcommands.
var touchidCmd = &cobra.Command{
	Use:   "touchid",
	Short: "enable or disable unlocking with Touch ID (macOS)",
	Long: `Touch ID unlock saves your master password in the macOS Keychain and
releases it after a successful fingerprint check. If Touch ID is unavailable or
cancelled, you are asked for the master password as before.`,
}

var touchidEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "unlock with Touch ID instead of typing the master password",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		utils.ManageErrorAndExit(utils.EnableBiometric())
		fmt.Println("Touch ID unlock enabled")
	},
}

var touchidDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "stop unlocking with Touch ID and remove the saved master password",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		utils.ManageErrorAndExit(utils.DisableBiometric())
		fmt.Println("Touch ID unlock disabled")
	},
}

func init() {
	touchidCmd.AddCommand(touchidEnableCmd, touchidDisableCmd)
	rootCmd.AddCommand(touchidCmd)
}
