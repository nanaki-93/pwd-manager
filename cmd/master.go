/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"crypto/rand"
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
	"os"
)

// masterCmd represents the master command
var masterCmd = &cobra.Command{
	Use:   "master",
	Short: "create or update your master password",
	Long:  ``,
	Run:   execMasterCmd,
}

func execMasterCmd(cmd *cobra.Command, args []string) {
	isToInit := false
	currPwdContent, err := utils.GetPwdObj()
	updatePwd := "y"
	if err != nil {
		generateKey()
		fmt.Println("You don't have a master password yet.")
		isToInit = true
	}
	if !isToInit {
		fmt.Println("Do you want to update your master password? (y/n)")
		_, err := fmt.Scanln(&updatePwd)
		utils.ManageErrorAndExit(err)
	}

	if isToInit || updatePwd == "y" {
		savePassword(currPwdContent)
	}

}
func savePassword(currPwdContent model.PwdFile) {
	var currPassword []byte
	var newPassword []byte
	var err error
	if currPwdContent.MasterPassword != "" {
		currPassword = utils.PromptPassword("Enter your current password:")
		if currPwdContent.MasterPassword != string(currPassword) {
			fmt.Println("Passwords do not match")
			return
		}
	}

	newPassword = utils.PromptPassword("Enter your new password:")
	currPwdContent.MasterPassword = string(newPassword)
	utils.SaveFile(currPwdContent, err)
	fmt.Println("Password saved")
}
func generateKey() {
	utils.GoToHomeDir()
	fmt.Println("Generating a key to encrypt your file:")
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		fmt.Println(err)
	}

	err = os.WriteFile(utils.PwdFileKey, key, 0700)
	utils.ManageErrorAndExit(err)
}
func init() {
	rootCmd.AddCommand(masterCmd)
}
