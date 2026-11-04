/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"errors"
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

// errPasswordNotFound is returned (wrapped) when the requested key is absent.
var errPasswordNotFound = errors.New("password not found")

func removePassword(name string, savedPasswords map[string]string, save func() error) error {
	if len(savedPasswords) == 0 {
		return fmt.Errorf("remove password %q: no passwords saved: %w", name, errPasswordNotFound)
	}
	prev, ok := savedPasswords[name]
	if !ok {
		return fmt.Errorf("remove password %q: %w", name, errPasswordNotFound)
	}
	delete(savedPasswords, name)
	if err := save(); err != nil {
		savedPasswords[name] = prev
		return fmt.Errorf("persist password removal for %q: %w", name, err)
	}
	fmt.Printf("%s removed\n", name)
	return nil
}

func execRemoveCmd(cmd *cobra.Command, args []string) {
	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	utils.ManageErrorAndExit(err)

	err = removePassword(nameFlag, pwdObj.SavedPasswords, func() error {
		utils.SaveFile(pwdObj, err)
		return nil
	})
	utils.ManageErrorAndExit(err)
}

func init() {
	rootCmd.AddCommand(removeCmd)

	removeCmd.Flags().StringVarP(&nameFlag, "name", "n", "", "The name of the password")
	err := removeCmd.MarkFlagRequired("name")
	utils.ManageErrorAndExit(err)
}
