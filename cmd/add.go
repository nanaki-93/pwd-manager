/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "",
	Run:   execAddCmd,
}

func init() {
	rootCmd.AddCommand(addCmd)
}

func execAddCmd(cmd *cobra.Command, args []string) {

	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	utils.ManageErrorAndExit(err)

	var pwdName string
	fmt.Println("Insert new name of the password:")
	_, err = fmt.Scanln(&pwdName)
	utils.ManageErrorAndExit(err)

	pwdValue := utils.PromptPassword("Insert the password for " + pwdName + ":")
	if pwdObj.SavedPasswords == nil {
		pwdObj.SavedPasswords = make(map[string]string)
	}
	pwdObj.SavedPasswords[pwdName] = string(pwdValue)
	utils.SaveFile(pwdObj, err)
}
