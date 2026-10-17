/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"golang.org/x/crypto/ssh/terminal"
)

const PwdFileName = ".pwd-mng"
const PwdFileKey = ".pwd-key"

func encryptFile(content []byte) {
	GoToHomeDir()
	// Reading key
	key, err := os.ReadFile(PwdFileKey)
	if err != nil {
		fmt.Printf("read file err: %v", err.Error())
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("cipher err: %v", err.Error())
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("cipher GCM err: %v", err.Error())
	}

	// Generating random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Printf("nonce  err: %v", err.Error())
	}

	// Decrypt file
	cipherText := gcm.Seal(nonce, nonce, content, nil)

	// Writing ciphertext file
	err = os.WriteFile(PwdFileName, cipherText, 0700)
	if err != nil {
		fmt.Printf("write file err: %v", err.Error())
	}

}

func GoToHomeDir() {
	home, err := os.UserHomeDir()
	ManageErrorAndExit(err)
	err = os.Chdir(home)
	ManageErrorAndExit(err)
}

func readPwdFile() ([]byte, error) {
	GoToHomeDir()
	// Reading ciphertext file
	cipherText, err := os.ReadFile(PwdFileName)
	if err != nil {
		return nil, err
	}

	// Reading key
	key, err := os.ReadFile(PwdFileKey)
	if err != nil {
		return nil, err
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("cipher err: %v", err.Error())
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("cipher GCM err: %v", err.Error())
	}

	// Deattached nonce and decrypt
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		fmt.Printf("decrypt file err: %v", err.Error())
	}

	return plainText, nil
}

func GetPwdObj() (model.PwdFile, error) {
	content := model.PwdFile{}

	fileContent, err := readPwdFile()
	if err != nil {
		return content, err
	}

	err = json.Unmarshal(fileContent, &content)
	if err != nil {
		fmt.Println(err)
		return content, err
	}

	return content, nil
}

func PromptPassword(textForPrompt string) []byte {
	fmt.Println(textForPrompt)
	promptedPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	ManageErrorAndExit(err)
	return promptedPassword
}

func SaveFile(currPwdContent model.PwdFile, err error) {
	jsonContent := toJsonContent(err, currPwdContent)
	encryptFile(jsonContent)
}

func toJsonContent(err error, pwdContent model.PwdFile) []byte {
	jsonContent, err := json.Marshal(pwdContent)
	ManageErrorAndExit(err)
	return jsonContent
}

func ManageErrorAndExit(err error) {
	if err != nil {
		fmt.Println(err)
		return
	}
}

func GetPwdObjAfterCheckMaster() (model.PwdFile, error) {
	pwdObj, err := GetPwdObj()
	if err != nil {
		ManageErrorAndExit(err)
		return model.PwdFile{}, err
	}
	pwd := PromptPassword("Enter your master password:")
	expectedHash := sha256.Sum256([]byte(pwdObj.MasterPassword))
	actualHash := sha256.Sum256(pwd)
	if subtle.ConstantTimeCompare(expectedHash[:], actualHash[:]) != 1 {
		return model.PwdFile{}, fmt.Errorf("master passwords do not match")
	}
	return pwdObj, nil
}
