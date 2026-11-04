package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

// generateKey must migrate a store encrypted with the legacy key file to the
// new key before removing that file, so the store stays readable.
func TestGenerateKeyMigratesLegacyStoreBeforeRemovingKeyFile(t *testing.T) {
	tmpHome := withTempHome(t)
	utils.SetMasterKey(nil)
	t.Cleanup(func() { utils.SetMasterKey(nil) })
	original := model.PwdFile{MasterPassword: hashFixture(t, "valid-master-secret"), SavedPasswords: map[string]string{"mail": "c2VjcmV0"}}
	seedLegacyVault(t, tmpHome, bytes.Repeat([]byte{0x42}, 32), original)

	if err := generateKey([]byte("valid-master-secret")); err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	loaded, err := utils.GetPwdObj()
	if err != nil || loaded.SavedPasswords["mail"] != "c2VjcmV0" || loaded.MasterPassword != original.MasterPassword {
		t.Fatalf("store unreadable after generateKey (err=%v, got %+v)", err, loaded)
	}
	if _, err := os.Stat(filepath.Join(tmpHome, utils.PwdFileKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy key file should be removed after migration, stat err: %v", err)
	}
}

func TestGenerateKeyKeepsLegacyKeyFileWhenSaveFails(t *testing.T) {
	tmpHome := withTempHome(t)
	utils.SetMasterKey(nil)
	t.Cleanup(func() { utils.SetMasterKey(nil) })
	legacyKey := bytes.Repeat([]byte{0x24}, 32)
	original := model.PwdFile{MasterPassword: hashFixture(t, "valid-master-secret"), SavedPasswords: map[string]string{"bank": "aHVudGVy"}}
	seedLegacyVault(t, tmpHome, legacyKey, original)
	storePath := filepath.Join(tmpHome, utils.PwdFileName)
	before, _ := os.ReadFile(storePath)
	saveErr := errors.New("disk full")
	stubSaveStore(t, saveErr)

	if err := generateKey([]byte("valid-master-secret")); !errors.Is(err, saveErr) {
		t.Fatalf("expected the failed save to be returned, got %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(tmpHome, utils.PwdFileKey)); err != nil || !bytes.Equal(got, legacyKey) {
		t.Fatalf("legacy key file removed or changed without re-encryption (err=%v)", err)
	}
	if got, _ := os.ReadFile(storePath); !bytes.Equal(got, before) {
		t.Fatalf("store modified by failed generateKey")
	}
	loaded, err := utils.GetPwdObj()
	if err != nil || loaded.SavedPasswords["bank"] != "aHVudGVy" {
		t.Fatalf("legacy store no longer readable (err=%v)", err)
	}
}

// hashFixture returns a stored master hash for password.
func hashFixture(t *testing.T, password string) string {
	t.Helper()
	hashed, err := utils.HashMasterPassword([]byte(password))
	if err != nil {
		t.Fatalf("hash fixture password: %v", err)
	}
	return hashed
}

// A password that does not match the stored hash must not re-key a store read
// through the legacy key file, or the user is locked out of it.
func TestGenerateKeyRejectsWrongPasswordForLegacyStore(t *testing.T) {
	tmpHome := withTempHome(t)
	utils.SetMasterKey(nil)
	t.Cleanup(func() { utils.SetMasterKey(nil) })
	legacyKey := bytes.Repeat([]byte{0x33}, 32)
	original := model.PwdFile{MasterPassword: hashFixture(t, "valid-master-secret"), SavedPasswords: map[string]string{"bank": "aHVudGVy"}}
	seedLegacyVault(t, tmpHome, legacyKey, original)
	storePath := filepath.Join(tmpHome, utils.PwdFileName)
	before, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read fixture store: %v", err)
	}

	if err := generateKey([]byte("wrong-master-secret")); !errors.Is(err, errCurrentPasswordMismatch) {
		t.Fatalf("expected a password mismatch error, got %v", err)
	}
	if got, err := os.ReadFile(storePath); err != nil || !bytes.Equal(got, before) {
		t.Fatalf("store changed after a wrong password (err=%v)", err)
	}
	if got, err := os.ReadFile(filepath.Join(tmpHome, utils.PwdFileKey)); err != nil || !bytes.Equal(got, legacyKey) {
		t.Fatalf("legacy key file removed or changed after a wrong password (err=%v)", err)
	}
	loaded, err := utils.GetPwdObj()
	if err != nil || loaded.SavedPasswords["bank"] != "aHVudGVy" {
		t.Fatalf("legacy store no longer readable after a wrong password (err=%v)", err)
	}
}

func TestGenerateKeyKeepsLegacyKeyFileWhenStoreUnreadable(t *testing.T) {
	tmpHome := withTempHome(t)
	utils.SetMasterKey([]byte("some-other-secret"))
	t.Cleanup(func() { utils.SetMasterKey(nil) })
	if err := utils.SaveFileErr(model.PwdFile{MasterPassword: "pbkdf2-sha256$x"}, nil); err != nil {
		t.Fatalf("write fixture store: %v", err)
	}
	utils.SetMasterKey(nil)
	legacyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	if err := os.WriteFile(legacyPath, bytes.Repeat([]byte{0x11}, 32), 0o600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}

	if err := generateKey([]byte("valid-master-secret")); err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy key file removed although the store was not re-encrypted: %v", err)
	}
}
