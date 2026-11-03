package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

// Observe the header at the save boundary, not just after rotation returns.
func TestRotateMasterKeyUpgradesRecordedHeaderBeforeSave(t *testing.T) {
	home := withTempHome(t)
	t.Cleanup(func() { utils.SetMasterKey(nil) })
	salt := bytes.Repeat([]byte{0x73}, keyDerivationSaltLen)
	data := binary.BigEndian.AppendUint32([]byte(keySaltMagic), 200_000)
	data = append(data, salt...)
	if err := os.WriteFile(filepath.Join(home, keyDerivationSaltFile), data, 0o600); err != nil {
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
	if err := rotateMasterKey(password, content); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if calls != 1 {
		t.Fatalf("save calls = %d, want 1", calls)
	}
	utils.SetMasterKey(pbkdf2Key(password, salt, keyDerivationIterations, encryptionKeyLen, sha256.New))
	loaded, err := utils.GetPwdObj()
	if err != nil || loaded.MasterPassword != content.MasterPassword || loaded.SavedPasswords["mail"] != "secret" {
		t.Fatalf("store not encrypted at upgraded count: content=%+v, err=%v", loaded, err)
	}
}
