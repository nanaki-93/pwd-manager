package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

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

func TestRotateMasterKeySuccessRecordsCurrentIterations(t *testing.T) {
	home := withTempHome(t)
	t.Cleanup(func() { utils.SetMasterKey(nil) })
	salt := bytes.Repeat([]byte{0x5a}, keyDerivationSaltLen)
	if err := os.WriteFile(filepath.Join(home, keyDerivationSaltFile), salt, 0o600); err != nil {
		t.Fatalf("seed salt: %v", err)
	}
	content := model.PwdFile{MasterPassword: "new-hash", SavedPasswords: map[string]string{"mail": "secret"}}
	password := []byte("valid-master-secret")
	if err := rotateMasterKey(password, content); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	iterations, stored := readStoredSaltParams(t, home)
	if iterations != keyDerivationIterations || !bytes.Equal(stored, salt) {
		t.Fatalf("salt header = (%d, %x), want (%d, kept salt)", iterations, stored, keyDerivationIterations)
	}
	utils.SetMasterKey(pbkdf2Key(password, salt, keyDerivationIterations, encryptionKeyLen, sha256.New))
	loaded, err := utils.GetPwdObj()
	if err != nil || loaded.SavedPasswords["mail"] != "secret" {
		t.Fatalf("store not saved under the new key: %+v, err=%v", loaded, err)
	}
}
