/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
	"io"
	"os"
	"strings"
)

const (
	minMasterPasswordLen    = 8
	encryptionKeyLen        = 32
	keyDerivationSaltLen    = 32
	keyDerivationIterations = 100_000
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
		if err := validateMasterPassword(pwd); err != nil {
			return err
		}
	}
	utils.GoToHomeDir()
	fmt.Println("Generating a key to encrypt your file:")
	salt := make([]byte, keyDerivationSaltLen)
	defer clear(salt)

	_, err := randRead(rand.Reader, salt)
	if err != nil {
		return fmt.Errorf("read random key bytes: %w", err)
	}

	derivedKey := pbkdf2SHA256(pwd, salt, keyDerivationIterations, encryptionKeyLen)
	defer clear(derivedKey)

	err = os.WriteFile(utils.PwdFileKey, derivedKey, 0600)
	if err != nil {
		return fmt.Errorf("write key file: %w", err)
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
	return pbkdf2SHA256(password, salt, keyDerivationIterations, encryptionKeyLen), nil
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var blockBuf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	t := make([]byte, hashLen)
	defer func() {
		clear(u)
		clear(t)
	}()

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(blockBuf[:], uint32(block))
		prf.Write(blockBuf[:])
		u = prf.Sum(u[:0])
		copy(t, u)

		for i := 2; i <= iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	result := make([]byte, keyLen)
	copy(result, dk[:keyLen])
	clear(dk)
	return result
}

func init() {
	rootCmd.AddCommand(masterCmd)
}
