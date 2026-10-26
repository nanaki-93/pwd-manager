/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
)

const maskedPasswordPlaceholder = "********"

var (
	listShowFlag bool
	listJSONFlag bool
)

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
	listCmd.Flags().BoolVar(&listJSONFlag, "json", false, "output saved passwords as formatted JSON")
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

func writeListJSONOutput(w io.Writer, savedPasswords map[string]string, showPlaintext bool) error {
	entries := make(map[string]string, len(savedPasswords))
	for k, v := range savedPasswords {
		if showPlaintext {
			entries[k] = v
		} else {
			entries[k] = maskedPasswordPlaceholder
		}
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal list json output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "%s\n", data); err != nil {
		return fmt.Errorf("write list json output: %w", err)
	}
	return nil
}

func runListCmd(out, errOut io.Writer, savedPasswords map[string]string, showPlaintext, asJSON bool) error {
	if asJSON {
		if err := writeListJSONOutput(out, savedPasswords, showPlaintext); err != nil {
			if errOut != nil {
				_, _ = fmt.Fprintf(errOut, "Error: %v\n", err)
			}
			return err
		}
		return nil
	}
	return writeListOutput(out, savedPasswords, showPlaintext)
}

func execListCmd(cmd *cobra.Command, args []string) {
	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	if err != nil {
		if listJSONFlag {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Error: %v\n", err)
		}
		utils.ManageErrorAndExit(err)
		return
	}
	err = runListCmd(cmd.OutOrStdout(), cmd.ErrOrStderr(), pwdObj.SavedPasswords, listShowFlag, listJSONFlag)
	utils.ManageErrorAndExit(err)
}
