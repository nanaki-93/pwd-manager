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

func removePassword(name string, savedPasswords map[string]string, save func() error) error {
	if len(savedPasswords) == 0 {
		fmt.Println("No passwords saved")
		return nil
	}
	prev, ok := savedPasswords[name]
	if !ok {
		fmt.Printf("Password with key '%s' not found\n", name)
		return nil
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
