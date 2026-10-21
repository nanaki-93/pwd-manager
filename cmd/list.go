/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"fmt"
	"io"
	"sort"

	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
)

const maskedPasswordPlaceholder = "********"

var listShowFlag bool

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "a list of all your saved passwords",
	Long:  ``,
	Run:   execListCmd,
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolVarP(&listShowFlag, "show", "s", false, "show saved passwords in plaintext")
}

func writeListOutput(w io.Writer, savedPasswords map[string]string, showPlaintext bool) error {
	keys := make([]string, 0, len(savedPasswords))
	for k := range savedPasswords {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		val := maskedPasswordPlaceholder
		if showPlaintext {
			val = savedPasswords[k]
		}
		if _, err := fmt.Fprintf(w, "%s: %s\n", k, val); err != nil {
			return fmt.Errorf("write list output: %w", err)
		}
	}
	return nil
}

func execListCmd(cmd *cobra.Command, args []string) {
	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	utils.ManageErrorAndExit(err)
	err = writeListOutput(cmd.OutOrStdout(), pwdObj.SavedPasswords, listShowFlag)
	utils.ManageErrorAndExit(err)
}
