package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

// seedLegacyVault writes a store encrypted with a raw key file, the format
// written before password-derived keys.
func seedLegacyVault(t *testing.T, tmpHome string, key []byte, content model.PwdFile) {
	t.Helper()
	plain, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal store: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := bytes.Repeat([]byte{0x01}, gcm.NonceSize())
	sealed := gcm.Seal(nonce, nonce, plain, nil)
	if err := os.WriteFile(filepath.Join(tmpHome, utils.PwdFileKey), key, 0o600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, utils.PwdFileName), sealed, 0o600); err != nil {
		t.Fatalf("write legacy store: %v", err)
	}
}

func stubSaveStore(t *testing.T, err error) {
	t.Helper()
	orig := saveStore
	t.Cleanup(func() { saveStore = orig })
	saveStore = func(model.PwdFile, error) error { return err }
}

func TestSavePasswordKeepsLegacyVaultWhenSaveFails(t *testing.T) {
	tmpHome := withTempHome(t)
	oldPwd := "original-master-pass"
	oldHash, err := utils.HashMasterPassword([]byte(oldPwd))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	legacyKey := bytes.Repeat([]byte{0x42}, 32)
	original := model.PwdFile{MasterPassword: oldHash, SavedPasswords: map[string]string{"mail": "c2VjcmV0"}}
	seedLegacyVault(t, tmpHome, legacyKey, original)
	vaultBefore, _ := os.ReadFile(filepath.Join(tmpHome, utils.PwdFileName))

	saveErr := errors.New("disk full")
	stubSaveStore(t, saveErr)
	stubPasswordSequence(t, oldPwd, "rotated-master-pass")
	exitCount := captureExit(t)
	savePassword(original)

	if *exitCount == 0 {
		t.Fatalf("expected the failed save to abort the rotation")
	}
	if got, err := os.ReadFile(filepath.Join(tmpHome, utils.PwdFileKey)); err != nil || !bytes.Equal(got, legacyKey) {
		t.Fatalf("legacy key file was removed or changed before the save succeeded (err=%v)", err)
	}
	if got, _ := os.ReadFile(filepath.Join(tmpHome, utils.PwdFileName)); !bytes.Equal(got, vaultBefore) {
		t.Fatalf("original store was modified by a failed rotation")
	}
	loaded, err := utils.GetPwdObj()
	if err != nil || loaded.SavedPasswords["mail"] != "c2VjcmV0" || !utils.VerifyMasterPassword(loaded.MasterPassword, []byte(oldPwd)) {
		t.Fatalf("original store no longer usable with the original password (err=%v)", err)
	}
	if err := utils.SaveFileErr(loaded, nil); !errors.Is(err, utils.ErrMasterKeyRequired) {
		t.Fatalf("new master key stayed in memory after the failed save: %v", err)
	}
}

func TestSavePasswordRemovesLegacyKeyAfterSuccessfulSave(t *testing.T) {
	tmpHome := withTempHome(t)
	oldPwd := "original-master-pass"
	oldHash, err := utils.HashMasterPassword([]byte(oldPwd))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	seedLegacyVault(t, tmpHome, bytes.Repeat([]byte{0x24}, 32), model.PwdFile{MasterPassword: oldHash})
	stubPasswordSequence(t, oldPwd, "rotated-master-pass")
	exitCount := captureExit(t)
	savePassword(model.PwdFile{MasterPassword: oldHash})

	if *exitCount != 0 {
		t.Fatalf("rotation aborted unexpectedly")
	}
	if _, err := os.Stat(filepath.Join(tmpHome, utils.PwdFileKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy key file should be removed after a successful save, stat err: %v", err)
	}
	loaded, err := utils.GetPwdObj()
	if err != nil || !utils.VerifyMasterPassword(loaded.MasterPassword, []byte("rotated-master-pass")) {
		t.Fatalf("rotated store not readable with the new key (err=%v)", err)
	}
}
