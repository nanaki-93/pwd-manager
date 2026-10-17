/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
	"io"
	"os"
)

var randRead = io.ReadFull

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
		if !errors.Is(err, os.ErrNotExist) {
			utils.ManageErrorAndExit(err)
			return
		}
		if err := generateKey(); err != nil {
			utils.ManageErrorAndExit(err)
			return
		}
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
func generateKey() error {
	utils.GoToHomeDir()
	fmt.Println("Generating a key to encrypt your file:")
	key := make([]byte, 32)

	_, err := randRead(rand.Reader, key)
	if err != nil {
		return err
	}

	err = os.WriteFile(utils.PwdFileKey, key, 0700)
	if err != nil {
		return err
	}
	return nil
}
func init() {
	rootCmd.AddCommand(masterCmd)
}
