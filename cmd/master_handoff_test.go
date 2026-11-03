package cmd

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func TestGeneratedKeyHandoffSurvivesDeferredWipe(t *testing.T) {
	withTempHome(t)
	stubFixedRandSalt(t, 0x51, nil)
	password := []byte("valid-master-secret")
	if err := generateKey(password); err != nil {
		t.Fatal(err)
	}
	content := model.PwdFile{MasterPassword: "test-hash", SavedPasswords: map[string]string{"site": "encoded-value"}}
	if err := utils.SaveFileErr(content, nil); err != nil {
		t.Fatalf("save after key handoff: %v", err)
	}
	// Replace the active key with an independently derived value. Successful
	// decryption proves the saved store used that value, not a wiped buffer.
	key := pbkdf2Key(password, bytes.Repeat([]byte{0x51}, 32), 600_000, 32, sha256.New)
	defer clear(key)
	utils.SetMasterKey(key)
	loaded, err := utils.GetPwdObj()
	if err != nil || loaded.MasterPassword != content.MasterPassword || loaded.SavedPasswords["site"] != "encoded-value" {
		t.Fatalf("store was not encrypted with the expected nonzero key: %v", err)
	}
}
