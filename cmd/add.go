/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
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
	addCmd.Flags().BoolVarP(&addCopyFlag, "copy", "c", false,
		"Copy the password to the clipboard (it is not cleared automatically and is readable by other local processes and clipboard history tools)")
}

func readPwdName(r io.Reader) (string, error) {
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read password name: %w", err)
	}
	pwdName := strings.TrimSpace(line)
	if pwdName == "" {
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read password name: no password name provided before end of input: %w", err)
		}
		return "", errors.New("password name cannot be empty")
	}
	if err := validatePwdName(pwdName); err != nil {
		return "", fmt.Errorf("read password name: %w", err)
	}
	return pwdName, nil
}

// maxPwdNameLen bounds the length, in characters, of an entry name.
const maxPwdNameLen = 128

// errInvalidPwdName reports an entry name that is too long, not valid UTF-8
// or contains non-printable characters such as control or escape bytes.
var errInvalidPwdName = errors.New("invalid password name")

// validatePwdName rejects names that could inject terminal escape sequences or
// control characters when echoed in prompts or listed from the vault later.
func validatePwdName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: not valid UTF-8", errInvalidPwdName)
	}
	if n := utf8.RuneCountInString(name); n > maxPwdNameLen {
		return fmt.Errorf("%w: %d characters exceeds the maximum of %d", errInvalidPwdName, n, maxPwdNameLen)
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("%w: contains non-printable character %q", errInvalidPwdName, r)
		}
	}
	return nil
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

// saveVault persists the vault; a package variable so tests can inject failures.
var saveVault = utils.SaveFileErr

// errEmptyPassword reports that the prompted password value was empty.
var errEmptyPassword = errors.New("password value cannot be empty")

// storePassword records pwdValue under pwdName and persists the vault,
// returning any save failure with context instead of relying on a stale error.
// An empty pwdValue is rejected before the vault is touched so it can never
// overwrite an existing entry. If the save fails, the caller's map is restored.
func storePassword(pwdObj model.PwdFile, pwdName, pwdValue string) error {
	if pwdValue == "" {
		return fmt.Errorf("save password %q: %w", pwdName, errEmptyPassword)
	}
	if pwdObj.SavedPasswords == nil {
		pwdObj.SavedPasswords = make(map[string]string)
	}
	// SavedPasswords is shared with the caller, so undo the change if the save
	// fails to keep the in-memory vault in sync with what was persisted.
	prev, existed := pwdObj.SavedPasswords[pwdName]
	pwdObj.SavedPasswords[pwdName] = pwdValue
	if err := saveVault(pwdObj, nil); err != nil {
		if existed {
			pwdObj.SavedPasswords[pwdName] = prev
		} else {
			delete(pwdObj.SavedPasswords, pwdName)
		}
		return fmt.Errorf("save password %q: %w", pwdName, err)
	}
	return nil
}

func execAddCmd(cmd *cobra.Command, args []string) {

	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	utils.ManageErrorAndExit(err)

	stdinReader := bufio.NewReader(os.Stdin)

	fmt.Println("Insert new name of the password:")
	pwdName, err := readPwdName(stdinReader)
	utils.ManageErrorAndExit(err)

	if pwdObj.SavedPasswords == nil {
		pwdObj.SavedPasswords = make(map[string]string)
	}
	proceed, err := canSavePassword(pwdObj.SavedPasswords, pwdName, stdinReader)
	utils.ManageErrorAndExit(err)
	if !proceed {
		fmt.Println("Operation cancelled")
		return
	}

	pwdBytes := utils.PromptPassword("Insert the password for " + pwdName + ":")
	if err := addPromptedPassword(pwdObj, pwdName, pwdBytes, addCopyFlag); err != nil {
		utils.ManageErrorAndExit(err)
		return
	}
}

// addPromptedPassword stores the prompted secret and optionally copies it to
// the clipboard. pwdBytes is always wiped before returning, on every path.
//
// This limits, but does not remove, copies of the secret in memory:
//   - An empty secret is rejected on the bytes, before any string exists.
//   - model.PwdFile stores values as strings, so the secret is converted to an
//     immutable string exactly once. That string cannot be wiped: it stays in
//     the vault map and in process memory until the garbage collector reuses it.
//   - The same string (not a new copy) is handed to the vault save, which
//     marshals it into a JSON buffer, and to the clipboard helper, which hands
//     it to the OS clipboard. Neither copy is wiped by this command.
//
// Process memory, core dumps and swap can therefore still expose the secret.
func addPromptedPassword(pwdObj model.PwdFile, pwdName string, pwdBytes []byte, copyToClipboard bool) error {
	defer clear(pwdBytes)
	if len(pwdBytes) == 0 {
		return fmt.Errorf("save password %q: %w", pwdName, errEmptyPassword)
	}
	pwdValue := string(pwdBytes)
	if err := storePassword(pwdObj, pwdName, pwdValue); err != nil {
		return err
	}
	if copyToClipboard {
		if err := copyPasswordToClipboard(pwdValue); err != nil {
			return fmt.Errorf("password %q saved, but %w", pwdName, err)
		}
	}
	return nil
}
