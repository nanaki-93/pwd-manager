/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
)

// removeCmd represents the remove command
var removeCmd = &cobra.Command{
	Use:   "remove",
	Short: "A brief description of your command",
	Run:   execRemoveCmd,
}

func execRemoveCmd(cmd *cobra.Command, args []string) {

	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	utils.ManageErrorAndExit(err)

	if len(pwdObj.SavedPasswords) == 0 {
		fmt.Printf("No passwords saved")
		return
	}
	if _, ok := pwdObj.SavedPasswords[nameFlag]; !ok {
		fmt.Printf("Password with key '%s' not found", nameFlag)
		return
	}
	delete(pwdObj.SavedPasswords, nameFlag)
	utils.SaveFile(pwdObj, err)
	fmt.Printf("%s removed", nameFlag)
}
func init() {
	rootCmd.AddCommand(removeCmd)

	removeCmd.Flags().StringVarP(&nameFlag, "name", "n", "", "The name of the password")
	err := removeCmd.MarkFlagRequired("name")
	utils.ManageErrorAndExit(err)
}
