package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func readStoredSaltParams(t *testing.T, tmpHome string) (int, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(tmpHome, keyDerivationSaltFile))
	if err != nil {
		t.Fatalf("read salt file: %v", err)
	}
	if len(data) != len(keySaltMagic)+4+keyDerivationSaltLen || !bytes.HasPrefix(data, []byte(keySaltMagic)) {
		t.Fatalf("salt file does not record KDF parameters: %x", data)
	}
	iter := int(binary.BigEndian.Uint32(data[len(keySaltMagic) : len(keySaltMagic)+4]))
	return iter, data[len(keySaltMagic)+4:]
}

// Rotation rewrites a legacy raw salt or a weaker recorded header at the
// current count before the store is saved under the matching key.
func TestRotateMasterKeyUpgradesSaltHeaderBeforeSave(t *testing.T) {
	salt := bytes.Repeat([]byte{0x73}, keyDerivationSaltLen)
	cases := map[string][]byte{
		"legacy raw salt":  salt,
		"weaker iteration": append(binary.BigEndian.AppendUint32([]byte(keySaltMagic), 200_000), salt...),
	}
	for name, seeded := range cases {
		t.Run(name, func(t *testing.T) {
			home := withTempHome(t)
			if err := os.WriteFile(filepath.Join(home, keyDerivationSaltFile), seeded, 0o600); err != nil {
				t.Fatalf("seed salt: %v", err)
			}
			originalSave := saveStore
			t.Cleanup(func() { saveStore = originalSave })
			calls := 0
			saveStore = func(content model.PwdFile, upstream error) error {
				calls++
				iterations, storedSalt := readStoredSaltParams(t, home)
				if iterations != keyDerivationIterations || !bytes.Equal(storedSalt, salt) {
					t.Fatalf("save began before upgraded header persisted: (%d, %x)", iterations, storedSalt)
				}
				return originalSave(content, upstream)
			}
			password := []byte("rotated-master-secret")
			content := model.PwdFile{MasterPassword: "fixture-hash", SavedPasswords: map[string]string{"mail": "secret"}}
			if err := rotateMasterKey(password, content); err != nil || calls != 1 {
				t.Fatalf("rotate: err=%v, save calls = %d, want 1", err, calls)
			}
			utils.SetMasterKey(password)
			loaded, err := utils.GetPwdObj()
			if err != nil || loaded.MasterPassword != content.MasterPassword || loaded.SavedPasswords["mail"] != "secret" {
				t.Fatalf("store not encrypted at upgraded count: content=%+v, err=%v", loaded, err)
			}
		})
	}
}

// A rotated store must unlock with the raw new password, the secret unlocking
// derives the store key from; installing the PBKDF2 output instead made the
// store encrypted under a key no unlock could reproduce.
func TestRotateMasterKeyThenUnlockStoreWithPassword(t *testing.T) {
	withTempHome(t)
	password := []byte("rotated-master-secret")
	hash, err := utils.HashMasterPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	content := model.PwdFile{MasterPassword: hash, SavedPasswords: map[string]string{"mail": "secret"}}
	if err := rotateMasterKey(password, content); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	utils.SetMasterKey(nil)
	loaded, err := utils.UnlockStore(password)
	if err != nil || loaded.SavedPasswords["mail"] != "secret" {
		t.Fatalf("rotated store did not unlock with the new password: content=%+v, err=%v", loaded, err)
	}
}

// A failed save must leave the salt file as it was: the store on disk is still
// encrypted under the key the previous salt file records.
func TestRotateMasterKeyFailedSaveKeepsSaltFile(t *testing.T) {
	salt := bytes.Repeat([]byte{0x5a}, keyDerivationSaltLen)
	outdated := append(binary.BigEndian.AppendUint32([]byte(keySaltMagic), 200_000), salt...)
	cases := map[string][]byte{"legacy": salt, "outdated": outdated, "absent": nil}
	for name, previous := range cases {
		t.Run(name, func(t *testing.T) {
			home := withTempHome(t)
			saltPath := filepath.Join(home, keyDerivationSaltFile)
			if previous != nil {
				if err := os.WriteFile(saltPath, previous, 0o600); err != nil {
					t.Fatalf("seed salt: %v", err)
				}
			}
			saveErr := errors.New("injected save failure")
			stubSaveStore(t, saveErr)
			err := rotateMasterKey([]byte("valid-master-secret"), model.PwdFile{MasterPassword: "new-hash"})
			if !errors.Is(err, saveErr) {
				t.Fatalf("rotate error = %v, want wrapped save failure", err)
			}
			got, readErr := os.ReadFile(saltPath)
			if previous == nil {
				if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("salt file left behind after failed save: %v", readErr)
				}
			} else if readErr != nil || !bytes.Equal(got, previous) {
				t.Fatalf("salt file changed after failed save: %x (err=%v)", got, readErr)
			}
			if err := utils.SaveFileErr(model.PwdFile{}, nil); !errors.Is(err, utils.ErrMasterKeyRequired) {
				t.Fatalf("new master key stayed in memory after the failed save: %v", err)
			}
		})
	}
}

func TestRotationPersistsSaltAndRetainsLegacyKeyBeforeSave(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			home := withTempHome(t)
			legacy := bytes.Repeat([]byte{0x42}, 32)
			seedLegacyVault(t, home, legacy, model.PwdFile{MasterPassword: "old-hash"})
			stubFixedRandSalt(t, 0x68, nil)
			saveErr := errors.New("injected save failure")
			originalSave := saveStore
			t.Cleanup(func() { saveStore = originalSave })
			calls := 0
			saveStore = func(content model.PwdFile, upstream error) error {
				calls++
				if content.MasterPassword != "new-hash" || upstream != nil {
					t.Fatal("save did not receive the new hash")
				}
				got, err := os.ReadFile(filepath.Join(home, utils.PwdFileKey))
				if err != nil || !bytes.Equal(got, legacy) {
					t.Fatalf("legacy key removed before save: %v", err)
				}
				iterations, salt := readStoredSaltParams(t, home)
				if iterations < minAcceptedKDFIterations || !bytes.Equal(salt, bytes.Repeat([]byte{0x68}, 32)) {
					t.Fatal("new salt and parameters were not persisted before save")
				}
				if fail {
					return saveErr
				}
				return originalSave(content, upstream)
			}
			err := rotateMasterKey([]byte("valid-master-secret"), model.PwdFile{MasterPassword: "new-hash"})
			if calls != 1 {
				t.Fatalf("save calls = %d, want 1", calls)
			}
			if fail {
				if !errors.Is(err, saveErr) || !strings.Contains(err.Error(), "save store with new master key:") {
					t.Fatalf("missing wrapped save context: %v", err)
				}
			} else if err != nil {
				t.Fatalf("rotation failed: %v", err)
			}
			assertLegacyKeyAfterSave(t, home, legacy, fail)
		})
	}
}

// assertLegacyKeyAfterSave checks the legacy key file is kept unchanged after
// a failed save and removed after a successful one.
func assertLegacyKeyAfterSave(t *testing.T, home string, legacy []byte, saveFailed bool) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(home, utils.PwdFileKey))
	if saveFailed {
		if err != nil || !bytes.Equal(got, legacy) {
			t.Fatalf("legacy key changed after failed save: %v", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy key kept after successful save: %v", err)
	}
}

func TestRotationSaltFailureDoesNotCallSaveOrRemoveLegacyKey(t *testing.T) {
	home := withTempHome(t)
	legacy := bytes.Repeat([]byte{0x42}, 32)
	seedLegacyVault(t, home, legacy, model.PwdFile{})
	stubFixedRandSalt(t, 0x68, nil)
	originalRand := randRead
	randRead = func(r io.Reader, salt []byte) (int, error) {
		n, err := originalRand(r, salt)
		if mkdirErr := os.Mkdir(filepath.Join(home, keyDerivationSaltFile), 0o700); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		return n, err
	}
	originalSave := saveStore
	t.Cleanup(func() { saveStore = originalSave })
	saveStore = func(model.PwdFile, error) error {
		t.Fatal("save called despite salt persistence failure")
		return nil
	}
	err := rotateMasterKey([]byte("valid-master-secret"), model.PwdFile{})
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Op != "write" || pathErr.Path != keyDerivationSaltFile {
		t.Fatalf("missing salt write context: %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(home, utils.PwdFileKey))
	if readErr != nil || !bytes.Equal(got, legacy) {
		t.Fatalf("legacy key changed after salt failure: %v", readErr)
	}
}

// A failed save during savePassword aborts the command and leaves the legacy
// vault usable with the original password.
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

	stubSaveStore(t, errors.New("disk full"))
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
}
