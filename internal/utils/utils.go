/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"golang.org/x/crypto/ssh/terminal"
)

const PwdFileName = ".pwd-mng"
const PwdFileKey = ".pwd-key"

const (
	hashPrefix     = "pbkdf2-sha256$"
	saltSize       = 16
	pbkdf2Iter     = 100000
	derivedKeySize = 32
)

var (
	exitFunc          = os.Exit
	randRead          = io.ReadFull
	readPasswordStdin = func() ([]byte, error) { return terminal.ReadPassword(int(syscall.Stdin)) }
)

// SetExitFunc overrides the process termination function for testing and returns a restore callback.
func SetExitFunc(fn func(int)) func() {
	prev := exitFunc
	exitFunc = fn
	return func() {
		exitFunc = prev
	}
}

// SetReadPasswordStdin overrides the password reader for testing and returns a restore callback.
func SetReadPasswordStdin(fn func() ([]byte, error)) func() {
	prev := readPasswordStdin
	readPasswordStdin = fn
	return func() {
		readPasswordStdin = prev
	}
}

// HashMasterPassword generates a salted PBKDF2-SHA256 hash of the supplied password.
func HashMasterPassword(password []byte) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := randRead(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	dk := pbkdf2SHA256(password, salt, pbkdf2Iter, derivedKeySize)
	return fmt.Sprintf("%s%s$%s", hashPrefix, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

// VerifyMasterPassword checks candidate against stored in constant time.
func VerifyMasterPassword(stored string, candidate []byte) bool {
	if stored == "" {
		return false
	}
	if strings.HasPrefix(stored, hashPrefix) {
		return verifyPBKDF2(strings.TrimPrefix(stored, hashPrefix), candidate)
	}
	expectedHash := sha256.Sum256([]byte(stored))
	actualHash := sha256.Sum256(candidate)
	return subtle.ConstantTimeCompare(expectedHash[:], actualHash[:]) == 1
}

func verifyPBKDF2(encoded string, candidate []byte) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil || len(salt) != saltSize {
		return false
	}
	expectedDK, err := hex.DecodeString(parts[1])
	if err != nil || len(expectedDK) != derivedKeySize {
		return false
	}
	actualDK := pbkdf2SHA256(candidate, salt, pbkdf2Iter, derivedKeySize)
	return subtle.ConstantTimeCompare(expectedDK, actualDK) == 1
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	if keyLen <= 0 {
		return nil
	}
	mac := hmac.New(sha256.New, password)
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)
	var intBuf [4]byte
	saltBlock := make([]byte, len(salt)+4)
	copy(saltBlock, salt)
	u := make([]byte, hashLen)
	uBuf := make([]byte, hashLen)
	t := make([]byte, hashLen)

	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(intBuf[:], uint32(block))
		copy(saltBlock[len(salt):], intBuf[:])

		mac.Reset()
		mac.Write(saltBlock)
		u = mac.Sum(u[:0])
		copy(t, u)

		for i := 2; i <= iter; i++ {
			mac.Reset()
			mac.Write(u)
			uBuf = mac.Sum(uBuf[:0])
			for j := range t {
				t[j] ^= uBuf[j]
			}
			u, uBuf = uBuf, u
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func encryptFile(content []byte) error {
	if err := chdirHome(); err != nil {
		return err
	}
	// Reading key
	key, err := os.ReadFile(PwdFileKey)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher init: %w", err)
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("cipher GCM init: %w", err)
	}

	// Generating random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := randRead(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt file
	cipherText := gcm.Seal(nonce, nonce, content, nil)

	// Writing ciphertext file
	if err := os.WriteFile(PwdFileName, cipherText, 0700); err != nil {
		return fmt.Errorf("write encrypted file: %w", err)
	}
	return nil
}

func chdirHome() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return os.Chdir(home)
}

func GoToHomeDir() {
	if err := chdirHome(); err != nil {
		ManageErrorAndExit(err)
	}
}

func readPwdFile() ([]byte, error) {
	if err := chdirHome(); err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("cipher err: %w", err)
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher GCM err: %w", err)
	}

	if len(cipherText) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Detached nonce and decrypt
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt file err: %w", err)
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

func PromptPasswordErr(textForPrompt string) ([]byte, error) {
	fmt.Println(textForPrompt)
	return readPasswordStdin()
}

func PromptPassword(textForPrompt string) []byte {
	promptedPassword, err := PromptPasswordErr(textForPrompt)
	ManageErrorAndExit(err)
	return promptedPassword
}

func SaveFileErr(currPwdContent model.PwdFile, err error) error {
	if err != nil {
		return err
	}
	jsonContent, marshalErr := toJsonContent(err, currPwdContent)
	if marshalErr != nil {
		return marshalErr
	}
	return encryptFile(jsonContent)
}

func SaveFile(currPwdContent model.PwdFile, err error) {
	if saveErr := SaveFileErr(currPwdContent, err); saveErr != nil {
		ManageErrorAndExit(saveErr)
	}
}

func toJsonContent(err error, pwdContent model.PwdFile) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	jsonContent, marshalErr := json.Marshal(pwdContent)
	if marshalErr != nil {
		return nil, marshalErr
	}
	return jsonContent, nil
}

func ManageErrorAndExit(err error) {
	if err != nil {
		fmt.Println(err)
		exitFunc(1)
	}
}

func GetPwdObjAfterCheckMaster() (model.PwdFile, error) {
	pwdObj, err := GetPwdObj()
	if err != nil {
		ManageErrorAndExit(err)
		return model.PwdFile{}, err
	}
	pwd := PromptPassword("Enter your master password:")
	if !VerifyMasterPassword(pwdObj.MasterPassword, pwd) {
		return model.PwdFile{}, fmt.Errorf("master passwords do not match")
	}
	return pwdObj, nil
}
