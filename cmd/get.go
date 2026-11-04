/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"errors"
	"fmt"
	"github.com/atotto/clipboard"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
	"os"
	"time"
)

var getCopyFlag bool
var clipboardWriteAll = clipboard.WriteAll

// getRevealFlag allows printing the plaintext password when standard output
// is not a terminal (pipes, redirected files, CI logs).
var getRevealFlag bool

// stdoutIsTerminal reports whether standard output is an interactive
// terminal; a package variable so tests can choose either path.
var stdoutIsTerminal = func() bool {
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// errRevealRequired reports a refused print to a non-terminal output.
var errRevealRequired = errors.New("refusing to print the password to non-terminal output; use --copy, or --reveal to print it anyway")

// getClearAfterFlag is how long `get --copy` keeps the password on the
// clipboard before clearing it.
var getClearAfterFlag = addClipboardClearDelay

// errInvalidClearAfter reports a non-positive --clear-after value.
var errInvalidClearAfter = errors.New("--clear-after must be a positive duration")

// errEmptyPasswordStore reports a lookup against a store with no passwords.
var errEmptyPasswordStore = errors.New("the password store is empty")

// errPasswordNotFound reports a lookup for a name that is not saved.
var errPasswordNotFound = errors.New("password not found")

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "get a password by name",
	Run:   execGetCmd,
}

func init() {
	rootCmd.AddCommand(getCmd)

	getCmd.Flags().StringVarP(&nameFlag, "name", "n", "", "The name of the password")
	getCmd.Flags().BoolVarP(&getCopyFlag, "copy", "c", false,
		"Copy the password to the clipboard; the command waits --clear-after (or Ctrl+C) and then clears it if unchanged. Until cleared it is readable by other local processes and clipboard history tools")
	getCmd.Flags().DurationVar(&getClearAfterFlag, "clear-after", addClipboardClearDelay,
		"With --copy, how long the password stays on the clipboard before it is cleared")
	getCmd.Flags().BoolVar(&getRevealFlag, "reveal", false,
		"Print the password even when standard output is not a terminal (pipes, files, logs). Without --copy the password is printed only to a terminal or with --reveal")
	err := getCmd.MarkFlagRequired("name")
	utils.ManageErrorAndExit(err)
}

func copyPasswordToClipboard(password string) error {
	if err := clipboardWriteAll(password); err != nil {
		wrappedErr := fmt.Errorf("failed to copy password to clipboard: %w", err)
		fmt.Println(wrappedErr)
		return wrappedErr
	}
	return nil
}

func handleGetOutput(name string, savedPasswords map[string]string, copyToClipboard bool) error {
	if len(savedPasswords) == 0 {
		return fmt.Errorf("get password '%s': %w; add one with 'pwd-manager add'", name, errEmptyPasswordStore)
	}
	pwd, ok := savedPasswords[name]
	if !ok {
		return fmt.Errorf("get password '%s': %w", name, errPasswordNotFound)
	}
	if copyToClipboard {
		return copyAndClearPassword(pwd, getClearAfterFlag)
	}
	return printPassword(name, pwd, getRevealFlag)
}

// printPassword writes name:pwd to stdout only when stdout is a terminal or
// reveal is set, warning on stderr that the secret is now visible.
func printPassword(name, pwd string, reveal bool) error {
	if !reveal && !stdoutIsTerminal() {
		return fmt.Errorf("get password '%s': %w", name, errRevealRequired)
	}
	fmt.Fprintln(os.Stderr, "Warning: printing the password in plaintext; it may persist in scrollback or logs (use --copy to avoid this).")
	fmt.Printf("%s:%s", name, pwd)
	return nil
}

// copyAndClearPassword copies pwd to the clipboard and then waits delay (or
// an interrupt) before clearing it, if the clipboard still holds pwd. The CLI
// exits right after `get`, so the clear cannot run in the background.
func copyAndClearPassword(pwd string, delay time.Duration) error {
	if delay <= 0 {
		return fmt.Errorf("copy password to clipboard: %w, got %v", errInvalidClearAfter, delay)
	}
	if err := copyPasswordToClipboard(pwd); err != nil {
		return err
	}
	if err := getClipboardClearer(pwd, delay); err != nil {
		return fmt.Errorf("password copied, but %w", err)
	}
	return nil
}

func execGetCmd(cmd *cobra.Command, args []string) {
	if getCopyFlag && getClearAfterFlag <= 0 {
		utils.ManageErrorAndExit(fmt.Errorf("get: %w, got %v", errInvalidClearAfter, getClearAfterFlag))
	}

	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	utils.ManageErrorAndExit(err)

	err = handleGetOutput(nameFlag, pwdObj.SavedPasswords, getCopyFlag)
	utils.ManageErrorAndExit(err)
}
