/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "a list of all your saved passwords",
	Long:  ``,
	Run:   execListCmd,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func execListCmd(cmd *cobra.Command, args []string) {

	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	utils.ManageErrorAndExit(err)
	for k, v := range pwdObj.SavedPasswords {
		fmt.Printf("%s: %s\n", k, v)
	}

}
