/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
	"io"
	"os"
)

const minMasterPasswordLen = 8

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
		if err != nil {
			utils.ManageErrorAndExit(err)
			return
		}
	}

	normalizedUpdate := strings.ToLower(strings.TrimSpace(updatePwd))
	if isToInit || normalizedUpdate == "y" || normalizedUpdate == "yes" {
		savePassword(currPwdContent)
	}

}
func savePassword(currPwdContent model.PwdFile) {
	var currPassword []byte
	var newPassword []byte
	defer func() {
		clear(currPassword)
		clear(newPassword)
	}()
	if currPwdContent.MasterPassword != "" {
		currPassword = utils.PromptPassword("Enter your current password:")
		matched := utils.VerifyMasterPassword(currPwdContent.MasterPassword, currPassword)
		clear(currPassword)
		if !matched {
			fmt.Println("Passwords do not match")
			return
		}
	}

	newPassword = utils.PromptPassword("Enter your new password:")
	if newPassword != nil {
		if err := validateMasterPassword(newPassword); err != nil {
			clear(newPassword)
			utils.ManageErrorAndExit(err)
			return
		}
	}
	hashedPassword, err := utils.HashMasterPassword(newPassword)
	clear(newPassword)
	if err != nil {
		utils.ManageErrorAndExit(err)
		return
	}
	currPwdContent.MasterPassword = hashedPassword
	if err := utils.SaveFileErr(currPwdContent, nil); err != nil {
		utils.ManageErrorAndExit(err)
		return
	}
	fmt.Println("Password saved")
}

func validateMasterPassword(password []byte) error {
	trimmed := bytes.TrimSpace(password)
	if len(trimmed) == 0 {
		return errors.New("master password cannot be empty")
	}
	if len(trimmed) < minMasterPasswordLen {
		return fmt.Errorf("master password must be at least %d characters long", minMasterPasswordLen)
	}
	return nil
}

func generateKey() error {
	utils.GoToHomeDir()
	fmt.Println("Generating a key to encrypt your file:")
	key := make([]byte, 32)
	defer clear(key)

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
