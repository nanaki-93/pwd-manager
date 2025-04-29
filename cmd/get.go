/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "get a password by name",
	Run:   execGetCmd,
}

func init() {
	rootCmd.AddCommand(getCmd)

	getCmd.Flags().StringVarP(&nameFlag, "name", "n", "", "The name of the password")
	err := getCmd.MarkFlagRequired("name")
	utils.ManageErrorAndExit(err)
}
func execGetCmd(cmd *cobra.Command, args []string) {

	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	utils.ManageErrorAndExit(err)

	if len(pwdObj.SavedPasswords) == 0 {
		fmt.Println("No passwords saved with ")
		return
	}
	if _, ok := pwdObj.SavedPasswords[nameFlag]; !ok {
		fmt.Printf("Password with key '%s' not found", nameFlag)
		return
	}
	fmt.Printf("%s:%s", nameFlag, pwdObj.SavedPasswords[nameFlag])
}
