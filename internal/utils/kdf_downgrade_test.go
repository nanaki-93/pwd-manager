/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

const testHigherPBKDF2Iter = 1000000

func hashAtIterations(password []byte, iter int) string {
	salt := bytes.Repeat([]byte{0x17}, saltSize)
	dk := kdf(password, salt, iter, derivedKeySize)
	return fmt.Sprintf("%s%d$%s$%s", hashPrefix, iter, hex.EncodeToString(salt), hex.EncodeToString(dk))
}

func writeV3StoreAtIterations(t *testing.T, secret []byte, content model.PwdFile, iter int) {
	t.Helper()
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	salt := bytes.Repeat([]byte{0x31}, saltSize)
	key := deriveEncryptionKey(secret, salt, iter)
	prefix := append([]byte(testV3Magic), binary.BigEndian.AppendUint32(nil, uint32(iter))...)
	prefix = append(prefix, salt...)
	if err := encryptFileWithRawKey(raw, key, prefix); err != nil {
		t.Fatalf("write v3 store: %v", err)
	}
}

func TestHashNeedsUpgrade_OnlyWeakerHashes(t *testing.T) {
	pwd := []byte("work-factor-secret")
	cases := []struct {
		stored string
		want   bool
	}{
		{legacyHash(t, pwd), true},
		{hashAtIterations(pwd, testLegacyPBKDF2Iter), true},
		{hashAtIterations(pwd, pbkdf2Iter), false},
		{hashAtIterations(pwd, testHigherPBKDF2Iter), false},
		{"not-a-hash", false},
	}
	for _, c := range cases {
		if got := hashNeedsUpgrade(c.stored); got != c.want {
			t.Errorf("hashNeedsUpgrade(%q) = %v, want %v", c.stored, got, c.want)
		}
	}
}

func TestUnlockKeepsHigherWorkFactor(t *testing.T) {
	home := withTempHome(t)
	secret := []byte("higher-work-factor-secret")
	stored := hashAtIterations(secret, testHigherPBKDF2Iter)
	original := model.PwdFile{MasterPassword: stored, SavedPasswords: map[string]string{"site": "value"}}
	writeV3StoreAtIterations(t, secret, original, testHigherPBKDF2Iter)
	before, err := os.ReadFile(filepath.Join(home, PwdFileName))
	if err != nil {
		t.Fatalf("read store: %v", err)
	}

	restore := SetReadPasswordStdin(func() ([]byte, error) { return append([]byte(nil), secret...), nil })
	defer restore()
	defer SetMasterKey(nil)

	got, err := GetPwdObjAfterCheckMaster()
	if err != nil {
		t.Fatalf("unlock store: %v", err)
	}
	if got.MasterPassword != stored {
		t.Fatalf("master hash rewritten on unlock: %q", got.MasterPassword)
	}
	if iter := readStoreIterations(t, home); iter != testHigherPBKDF2Iter {
		t.Fatalf("store iterations after unlock = %d, want %d", iter, testHigherPBKDF2Iter)
	}
	after, err := os.ReadFile(filepath.Join(home, PwdFileName))
	if err != nil {
		t.Fatalf("read store after unlock: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("store rewritten on unlock")
	}
}
