/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
	"io"
	"os"
	"strings"
)

var addCopyFlag bool

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "",
	Run:   execAddCmd,
}

func init() {
	rootCmd.AddCommand(addCmd)
	addCmd.Flags().BoolVarP(&addCopyFlag, "copy", "c", false, "Copy the password to the clipboard")
}

func readPwdName(r io.Reader) (string, error) {
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	pwdName := strings.TrimSpace(line)
	if pwdName == "" {
		if errors.Is(err, io.EOF) {
			return "", err
		}
		return "", errors.New("password name cannot be empty")
	}
	return pwdName, nil
}

func canSavePassword(savedPasswords map[string]string, pwdName string, r io.Reader) (bool, error) {
	if _, exists := savedPasswords[pwdName]; !exists {
		return true, nil
	}
	fmt.Printf("Password for %s already exists. Do you want to overwrite it? (y/n)\n", pwdName)
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(line), "y"), nil
}

func execAddCmd(cmd *cobra.Command, args []string) {

	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	utils.ManageErrorAndExit(err)

	fmt.Println("Insert new name of the password:")
	pwdName, err := readPwdName(os.Stdin)
	utils.ManageErrorAndExit(err)

	if pwdObj.SavedPasswords == nil {
		pwdObj.SavedPasswords = make(map[string]string)
	}
	proceed, err := canSavePassword(pwdObj.SavedPasswords, pwdName, os.Stdin)
	utils.ManageErrorAndExit(err)
	if !proceed {
		fmt.Println("Operation cancelled")
		return
	}

	pwdValue := utils.PromptPassword("Insert the password for " + pwdName + ":")
	pwdObj.SavedPasswords[pwdName] = string(pwdValue)
	utils.SaveFile(pwdObj, err)
	if addCopyFlag {
		_ = copyPasswordToClipboard(string(pwdValue))
	}
}
