/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"fmt"
	"github.com/atotto/clipboard"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
)

var getCopyFlag bool
var clipboardWriteAll = clipboard.WriteAll

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "get a password by name",
	Run:   execGetCmd,
}

func init() {
	rootCmd.AddCommand(getCmd)

	getCmd.Flags().StringVarP(&nameFlag, "name", "n", "", "The name of the password")
	getCmd.Flags().BoolVarP(&getCopyFlag, "copy", "c", false, "Copy the password to the clipboard")
	err := getCmd.MarkFlagRequired("name")
	utils.ManageErrorAndExit(err)
}

func copyPasswordToClipboard(password string) error {
	if err := clipboardWriteAll(password); err != nil {
		fmt.Printf("failed to copy password to clipboard: %v\n", err)
		return err
	}
	return nil
}

func handleGetOutput(name string, savedPasswords map[string]string, copyToClipboard bool) {
	if len(savedPasswords) == 0 {
		fmt.Println("No passwords saved with ")
		return
	}
	pwd, ok := savedPasswords[name]
	if !ok {
		fmt.Printf("Password with key '%s' not found", name)
		return
	}
	if copyToClipboard {
		_ = copyPasswordToClipboard(pwd)
		return
	}
	fmt.Printf("%s:%s", name, pwd)
}

func execGetCmd(cmd *cobra.Command, args []string) {

	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	utils.ManageErrorAndExit(err)

	handleGetOutput(nameFlag, pwdObj.SavedPasswords, getCopyFlag)
}
