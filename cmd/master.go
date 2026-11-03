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
		answer, err := readConfirmation(os.Stdin)
		if err != nil {
			utils.ManageErrorAndExit(err)
			return
		}
		updatePwd = answer
	}

	normalizedUpdate := strings.ToLower(strings.TrimSpace(updatePwd))
	if isToInit || normalizedUpdate == "y" || normalizedUpdate == "yes" {
		savePassword(currPwdContent)
	}

}

// readConfirmation reads one answer line from r a byte at a time, so input meant
// for later prompts is left unread. An empty line or closed input (EOF) yields
// an empty answer, which callers treat as a decline; other read errors are returned.
func readConfirmation(r io.Reader) (string, error) {
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n > 0 {
			if b[0] == '\n' {
				return string(line), nil
			}
			line = append(line, b[0])
		}
		if errors.Is(err, io.EOF) {
			return string(line), nil
		}
		if err != nil {
			return "", fmt.Errorf("read update confirmation: %w", err)
		}
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
	currPwdContent.MasterPassword = hashedPassword
	err = rotateMasterKey(newPassword, currPwdContent)
	clear(newPassword)
	if err != nil {
		utils.ManageErrorAndExit(err)
		return
	}
	fmt.Println("Password saved")
}

// saveStore re-encrypts and writes the store; a variable so tests can fail it.
// utils.SaveFileErr writes to a synced temporary file and renames it into place.
var saveStore = utils.SaveFileErr

// rotateMasterKey derives the key for password and re-saves content with it.
// Nothing the current store depends on is destroyed before the save succeeds:
// the legacy key file is removed only afterwards, and on a failed save the new
// key is dropped from memory so it cannot be used for later saves.
func rotateMasterKey(password []byte, content model.PwdFile) error {
	pending, err := prepareKey(password)
	if err != nil {
		return err
	}
	defer pending.wipe()
	if err := checkLegacyKeyFile(); err != nil {
		return err
	}
	// The salt is written first so a saved store never depends on an unsaved
	// salt; an existing salt keeps its bytes and only gains the parameter header.
	if err := pending.persistSalt(); err != nil {
		return err
	}
	utils.SetMasterKey(pending.key)
	if err := saveStore(content, nil); err != nil {
		utils.SetMasterKey(nil)
		return fmt.Errorf("save store with new master key: %w", err)
	}
	return removeLegacyKeyFile()
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
	pending, err := prepareKey(pwd)
	if err != nil {
		return err
	}
	defer pending.wipe()
	if err := checkLegacyKeyFile(); err != nil {
		return err
	}
	if err := pending.persistSalt(); err != nil {
		return err
	}
	if err := removeLegacyKeyFile(); err != nil {
		return err
	}
	utils.SetMasterKey(pending.key)
	return nil
}

// pendingKey is a derived key that has not been put into use yet.
type pendingKey struct {
	salt      []byte
	key       []byte
	writeSalt bool
}

func (p *pendingKey) wipe() {
	clear(p.salt)
	clear(p.key)
}

// persistSalt writes new salts and salt files with outdated parameters with
// the current KDF parameters.
func (p *pendingKey) persistSalt() error {
	if !p.writeSalt {
		return nil
	}
	return writeKeySalt(p.salt)
}

// prepareKey loads or creates the salt and derives the key for pwd without
// changing any file or the in-memory master key.
func prepareKey(pwd []byte) (*pendingKey, error) {
	if err := validateMasterPassword(pwd); err != nil {
		return nil, err
	}
	utils.GoToHomeDir()
	fmt.Println("Generating a key to encrypt your file:")
	salt := make([]byte, keyDerivationSaltLen)
	iterations, loaded, err := loadOrCreateKeySalt(salt)
	if err != nil {
		clear(salt)
		return nil, err
	}
	derivedKey, err := deriveKey(pwd, salt)
	if err != nil {
		clear(salt)
		return nil, err
	}
	return &pendingKey{salt: salt, key: derivedKey, writeSalt: !loaded || iterations != keyDerivationIterations}, nil
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
	if err := writeFileAtomic(keyDerivationSaltFile, data); err != nil {
		return fmt.Errorf("write salt file: %w", err)
	}
	return nil
}

// writeFileAtomic writes data to a synced temporary file next to path and
// renames it into place, so an interrupted write never truncates path.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(".", path+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if err := writeAndSync(tmp, data); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

func writeAndSync(f *os.File, data []byte) error {
	err := f.Chmod(0o600)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	return nil
}

// checkLegacyKeyFile fails when the legacy key path exists but is not a regular
// file, so rotation stops before anything is written.
func checkLegacyKeyFile() error {
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
	return nil
}

func removeLegacyKeyFile() error {
	if err := checkLegacyKeyFile(); err != nil {
		return err
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
