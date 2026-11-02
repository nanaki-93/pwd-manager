/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

func fakePasswordStdin(t *testing.T, pwd string) {
	t.Helper()
	restore := SetReadPasswordStdin(func() ([]byte, error) { return []byte(pwd), nil })
	t.Cleanup(restore)
}

func writeV3Store(t *testing.T, secret []byte, content model.PwdFile) {
	t.Helper()
	SetMasterKey(secret)
	if err := SaveFileErr(content, nil); err != nil {
		t.Fatalf("write v3 store: %v", err)
	}
	SetMasterKey(nil)
}

// A v3 store authenticated by the password-derived key proves the password, so
// unlock must not run a second PBKDF2 over the embedded hash. The embedded
// value here is not a valid hash: the redundant check would reject it.
func TestGetPwdObjAfterCheckMaster_V3SkipsRedundantHashCheck(t *testing.T) {
	withTempHome(t)
	writeV3Store(t, []byte("v3-unlock-secret"), model.PwdFile{
		MasterPassword: "not-a-pbkdf2-hash",
		SavedPasswords: map[string]string{"site": "value"},
	})
	fakePasswordStdin(t, "v3-unlock-secret")

	got, err := GetPwdObjAfterCheckMaster()
	if err != nil {
		t.Fatalf("unlock v3 store: %v", err)
	}
	if got.MasterPassword != "not-a-pbkdf2-hash" || got.SavedPasswords["site"] != "value" {
		t.Fatalf("unexpected store content: %+v", got)
	}
}

func TestGetPwdObjAfterCheckMaster_V3WrongPasswordFails(t *testing.T) {
	withTempHome(t)
	writeV3Store(t, []byte("v3-right-secret"), model.PwdFile{MasterPassword: "x"})
	fakePasswordStdin(t, "v3-wrong-secret")

	got, err := GetPwdObjAfterCheckMaster()
	if err == nil || err.Error() != "master passwords do not match" {
		t.Fatalf("expected decrypt failure mapped to mismatch, got %v", err)
	}
	if got.MasterPassword != "" || len(getMasterKey()) != 0 {
		t.Fatalf("failed unlock must return empty store and clear the master key")
	}
}

func writeKeyFileStore(t *testing.T, home string, content model.PwdFile) {
	t.Helper()
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	key := bytes.Repeat([]byte{0x33}, 32)
	if err := encryptFileWithRawKey(raw, key, nil); err != nil {
		t.Fatalf("write key-file store: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, PwdFileKey), key, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
}

// Legacy key-file stores decrypt without the password, so the hash still decides.
func TestGetPwdObjAfterCheckMaster_KeyFileStoreVerifiesHash(t *testing.T) {
	home := withTempHome(t)
	secret := []byte("key-file-secret")
	writeKeyFileStore(t, home, model.PwdFile{
		MasterPassword: legacyHash(t, secret),
		SavedPasswords: map[string]string{"site": "value"},
	})

	fakePasswordStdin(t, "key-file-wrong")
	if _, err := GetPwdObjAfterCheckMaster(); err == nil || err.Error() != "master passwords do not match" {
		t.Fatalf("wrong password on key-file store must fail hash check, got %v", err)
	}

	fakePasswordStdin(t, string(secret))
	got, err := GetPwdObjAfterCheckMaster()
	if err != nil {
		t.Fatalf("unlock key-file store: %v", err)
	}
	if got.SavedPasswords["site"] != "value" || !VerifyMasterPassword(got.MasterPassword, secret) {
		t.Fatalf("unexpected store content after unlock: %+v", got)
	}
}
