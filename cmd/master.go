/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
	"strings"
)

const (
	minMasterPasswordLen = 8
	encryptionKeyLen     = 32
	keyDerivationSaltLen = 32
	// keyDerivationIterations is the PBKDF2-HMAC-SHA256 work factor (OWASP guidance).
	// It is recorded in the salt file header so it can be raised later.
	keyDerivationIterations = 600_000
	// legacyKeyDerivationIterations is the work factor implied by salt files
	// written before parameters were recorded (raw salt bytes only).
	legacyKeyDerivationIterations = 100_000
	maxKeyDerivationIterations    = 10_000_000
	keyDerivationSaltFile         = ".pwd-salt"
	// keySaltMagic starts a salt file of the form magic | uint32 BE iterations | salt.
	keySaltMagic     = "PWS1"
	keySaltHeaderLen = len(keySaltMagic) + 4
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
	if err := validateMasterPassword(newPassword); err != nil {
		clear(newPassword)
		utils.ManageErrorAndExit(err)
		return
	}
	hashedPassword, err := utils.HashMasterPassword(newPassword)
	if err != nil {
		clear(newPassword)
		utils.ManageErrorAndExit(err)
		return
	}
	if err := generateKey(newPassword); err != nil {
		clear(newPassword)
		utils.ManageErrorAndExit(err)
		return
	}
	clear(newPassword)
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

func generateKey(password ...[]byte) error {
	var pwd []byte
	if len(password) > 0 {
		pwd = password[0]
	}
	if err := validateMasterPassword(pwd); err != nil {
		return err
	}
	utils.GoToHomeDir()
	fmt.Println("Generating a key to encrypt your file:")
	salt := make([]byte, keyDerivationSaltLen)
	defer clear(salt)

	iterations, loaded, err := loadOrCreateKeySalt(salt)
	if err != nil {
		return err
	}

	derivedKey, err := deriveKey(pwd, salt)
	if err != nil {
		return err
	}
	defer clear(derivedKey)

	if err := removeLegacyKeyFile(); err != nil {
		return err
	}
	// New salts and salt files with outdated parameters are (re)written with
	// the current KDF parameters; the new key is used for all later saves.
	if !loaded || iterations != keyDerivationIterations {
		if err := writeKeySalt(salt); err != nil {
			return err
		}
	}
	utils.SetMasterKey(derivedKey)
	return nil
}

// loadOrCreateKeySalt fills salt from the salt file, or with random bytes when
// there is none, and returns the PBKDF2 iterations recorded with a loaded salt.
func loadOrCreateKeySalt(salt []byte) (int, bool, error) {
	iterations, loaded, err := readKeySalt(salt)
	if err != nil || loaded {
		return iterations, loaded, err
	}
	if _, err := randRead(rand.Reader, salt); err != nil {
		return 0, false, fmt.Errorf("read random key bytes: %w", err)
	}
	return keyDerivationIterations, false, nil
}

// readKeySalt loads the salt file into salt and returns its recorded PBKDF2
// iterations. Legacy files holding only the raw salt imply legacyKeyDerivationIterations.
func readKeySalt(salt []byte) (int, bool, error) {
	info, err := os.Lstat(keyDerivationSaltFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("stat salt file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return 0, false, &os.PathError{Op: "open", Path: keyDerivationSaltFile, Err: errors.New("not a regular file")}
	}
	data, err := os.ReadFile(keyDerivationSaltFile)
	if err != nil {
		return 0, false, fmt.Errorf("read salt file: %w", err)
	}
	defer clear(data)
	iterations, raw, err := parseKeySalt(data, len(salt))
	if err != nil {
		return 0, false, err
	}
	copy(salt, raw)
	return iterations, true, nil
}

func parseKeySalt(data []byte, saltLen int) (int, []byte, error) {
	if len(data) == saltLen {
		return legacyKeyDerivationIterations, data, nil
	}
	if len(data) != keySaltHeaderLen+saltLen || !bytes.HasPrefix(data, []byte(keySaltMagic)) {
		return 0, nil, fmt.Errorf("invalid salt file length: got %d, want %d", len(data), keySaltHeaderLen+saltLen)
	}
	iter := uint64(binary.BigEndian.Uint32(data[len(keySaltMagic):keySaltHeaderLen]))
	if iter < legacyKeyDerivationIterations || iter > maxKeyDerivationIterations {
		return 0, nil, fmt.Errorf("unsupported PBKDF2 iteration count %d in salt file", iter)
	}
	return int(iter), data[keySaltHeaderLen:], nil
}

func writeKeySalt(salt []byte) error {
	if len(salt) == 0 {
		return errors.New("key derivation salt cannot be empty")
	}
	info, err := os.Lstat(keyDerivationSaltFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat salt file: %w", err)
	}
	if err == nil && !info.Mode().IsRegular() {
		return &os.PathError{Op: "write", Path: keyDerivationSaltFile, Err: errors.New("not a regular file")}
	}
	data := make([]byte, 0, keySaltHeaderLen+len(salt))
	data = append(data, keySaltMagic...)
	data = binary.BigEndian.AppendUint32(data, uint32(keyDerivationIterations))
	data = append(data, salt...)
	defer clear(data)
	if err := os.WriteFile(keyDerivationSaltFile, data, 0o600); err != nil {
		return fmt.Errorf("write salt file: %w", err)
	}
	return nil
}

func removeLegacyKeyFile() error {
	info, err := os.Lstat(utils.PwdFileKey)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return &os.PathError{Op: "remove", Path: utils.PwdFileKey, Err: errors.New("not a regular file")}
	}
	if err := os.Remove(utils.PwdFileKey); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove key file: %w", err)
	}
	return nil
}

func deriveKey(password, salt []byte) ([]byte, error) {
	if err := validateMasterPassword(password); err != nil {
		return nil, err
	}
	if len(salt) == 0 {
		return nil, errors.New("key derivation salt cannot be empty")
	}
	return pbkdf2.Key(password, salt, keyDerivationIterations, encryptionKeyLen, sha256.New), nil
}

func init() {
	rootCmd.AddCommand(masterCmd)
}
