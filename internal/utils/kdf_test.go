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
	"strconv"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

const (
	minRecommendedPBKDF2Iter = 600000
	testLegacyPBKDF2Iter     = 100000
	testV3Magic              = "PWD3"
	testIterFieldSize        = 4
)

func legacyHash(t *testing.T, password []byte) string {
	t.Helper()
	salt := bytes.Repeat([]byte{0x42}, saltSize)
	dk := kdf(password, salt, testLegacyPBKDF2Iter, derivedKeySize)
	return fmt.Sprintf("%s%s$%s", hashPrefix, hex.EncodeToString(salt), hex.EncodeToString(dk))
}

func legacyEncryptionKey(secret, salt []byte) []byte {
	domainSalt := make([]byte, 0, len(salt)+len("enc-v2")+1)
	domainSalt = append(domainSalt, salt...)
	domainSalt = append(domainSalt, ':')
	domainSalt = append(domainSalt, "enc-v2"...)
	return kdf(secret, domainSalt, testLegacyPBKDF2Iter, derivedKeySize)
}

func writeLegacyV2Store(t *testing.T, secret []byte, content model.PwdFile) {
	t.Helper()
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	salt := bytes.Repeat([]byte{0x24}, saltSize)
	key := legacyEncryptionKey(secret, salt)
	prefix := append([]byte(v2Magic), salt...)
	if err := encryptFileWithRawKey(raw, key, prefix); err != nil {
		t.Fatalf("write legacy v2 store: %v", err)
	}
}

func readStoreIterations(t *testing.T, home string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, PwdFileName))
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte(testV3Magic)) || len(raw) < len(testV3Magic)+testIterFieldSize {
		t.Fatalf("store header does not record KDF parameters: %q", raw[:min(len(raw), 8)])
	}
	return int(binary.BigEndian.Uint32(raw[len(testV3Magic):]))
}

func readStoreSalt(t *testing.T, home string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, PwdFileName))
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	start := len(testV3Magic) + testIterFieldSize
	if !bytes.HasPrefix(raw, []byte(testV3Magic)) || len(raw) < start+saltSize {
		t.Fatalf("store is not a v3 store")
	}
	return append([]byte(nil), raw[start:start+saltSize]...)
}

func TestSaveFile_ReusesDerivedKeyWithinSession(t *testing.T) {
	home := withTempHome(t)
	secret := []byte("cached-key-secret")
	SetMasterKey(secret)
	defer SetMasterKey(nil)
	if err := SaveFileErr(model.PwdFile{MasterPassword: "first"}, nil); err != nil {
		t.Fatalf("first save: %v", err)
	}
	firstSalt := readStoreSalt(t, home)
	firstRaw, _ := os.ReadFile(filepath.Join(home, PwdFileName))

	// A fresh session that loads then saves must reuse the key derived on decrypt.
	SetMasterKey(nil)
	SetMasterKey(secret)
	if _, err := GetPwdObj(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := SaveFileErr(model.PwdFile{MasterPassword: "second"}, nil); err != nil {
		t.Fatalf("second save: %v", err)
	}
	if !bytes.Equal(readStoreSalt(t, home), firstSalt) {
		t.Fatalf("save after load re-derived the key with a fresh salt")
	}
	secondRaw, _ := os.ReadFile(filepath.Join(home, PwdFileName))
	if bytes.Equal(firstRaw, secondRaw) {
		t.Fatalf("writes with the cached key must still produce unique ciphertext")
	}

	SetMasterKey(nil)
	SetMasterKey(secret)
	got, err := GetPwdObj()
	if err != nil || got.MasterPassword != "second" {
		t.Fatalf("store written with cached key does not decrypt: %+v, %v", got, err)
	}
	// Clearing and re-setting the master key without loading must not reuse the previous salt.
	SetMasterKey(nil)
	SetMasterKey(secret)
	if err := SaveFileErr(model.PwdFile{MasterPassword: "third"}, nil); err != nil {
		t.Fatalf("third save: %v", err)
	}
	if bytes.Equal(readStoreSalt(t, home), firstSalt) {
		t.Fatalf("SetMasterKey(nil) must clear the cached derived key")
	}
}

func TestSaveFile_PasswordChangeReDerivesKey(t *testing.T) {
	home := withTempHome(t)
	SetMasterKey([]byte("old-secret"))
	defer SetMasterKey(nil)
	if err := SaveFileErr(model.PwdFile{MasterPassword: "a"}, nil); err != nil {
		t.Fatalf("save: %v", err)
	}
	oldSalt := readStoreSalt(t, home)
	SetMasterKey([]byte("new-secret"))
	if err := SaveFileErr(model.PwdFile{MasterPassword: "b"}, nil); err != nil {
		t.Fatalf("save with new password: %v", err)
	}
	if bytes.Equal(readStoreSalt(t, home), oldSalt) {
		t.Fatalf("changing the password must re-derive the key with a fresh salt")
	}
	SetMasterKey(nil)
	SetMasterKey([]byte("new-secret"))
	if got, err := GetPwdObj(); err != nil || got.MasterPassword != "b" {
		t.Fatalf("store not readable with new password: %+v, %v", got, err)
	}
	SetMasterKey([]byte("old-secret"))
	if _, err := GetPwdObj(); err == nil {
		t.Fatalf("store must not decrypt with the old password")
	}
}

func hashIterations(t *testing.T, stored string) int {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(stored, hashPrefix), "$")
	if !strings.HasPrefix(stored, hashPrefix) || len(parts) != 3 {
		t.Fatalf("hash %q does not record an iteration count", stored)
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Fatalf("hash %q has non-numeric iteration count: %v", stored, err)
	}
	return n
}

func TestHashMasterPassword_RecordsStrongIterations(t *testing.T) {
	hashed, err := HashMasterPassword([]byte("strong-kdf-secret"))
	if err != nil {
		t.Fatalf("HashMasterPassword: %v", err)
	}
	if got := hashIterations(t, hashed); got < minRecommendedPBKDF2Iter {
		t.Fatalf("hash iterations = %d, want >= %d", got, minRecommendedPBKDF2Iter)
	}
}

func TestSaveFile_HeaderRecordsStrongIterations(t *testing.T) {
	home := withTempHome(t)
	SetMasterKey([]byte("header-kdf-secret"))
	if err := SaveFileErr(model.PwdFile{MasterPassword: "x"}, nil); err != nil {
		t.Fatalf("SaveFileErr: %v", err)
	}
	if got := readStoreIterations(t, home); got < minRecommendedPBKDF2Iter {
		t.Fatalf("store header iterations = %d, want >= %d", got, minRecommendedPBKDF2Iter)
	}
	if _, err := GetPwdObj(); err != nil {
		t.Fatalf("GetPwdObj on v3 store: %v", err)
	}
}

func TestVerifyMasterPassword_LegacyAndBoundedIterations(t *testing.T) {
	pwd := []byte("legacy-format-secret")
	stored := legacyHash(t, pwd)
	if !VerifyMasterPassword(stored, pwd) || VerifyMasterPassword(stored, []byte("wrong")) {
		t.Fatalf("legacy hash without iteration field must still verify correctly")
	}
	rest := strings.TrimPrefix(stored, hashPrefix)
	for _, iter := range []string{"1", "99999", "4294967296", "-5"} {
		if VerifyMasterPassword(hashPrefix+iter+"$"+rest, pwd) {
			t.Errorf("hash with out-of-range iteration count %s accepted", iter)
		}
	}
}

func TestGetPwdObj_V3RejectsOutOfRangeIterations(t *testing.T) {
	home := withTempHome(t)
	SetMasterKey([]byte("bounds-secret"))
	defer SetMasterKey(nil)
	storePath := filepath.Join(home, PwdFileName)
	raw := make([]byte, len(testV3Magic)+testIterFieldSize+saltSize+32)
	copy(raw, testV3Magic)
	binary.BigEndian.PutUint32(raw[len(testV3Magic):], 0xFFFFFFFF)
	if err := os.WriteFile(storePath, raw, 0600); err != nil {
		t.Fatalf("write store: %v", err)
	}
	if _, err := GetPwdObj(); err == nil || !strings.Contains(err.Error(), "unsupported PBKDF2 iteration count") {
		t.Fatalf("expected out-of-range iteration error, got %v", err)
	}
	if err := os.WriteFile(storePath, []byte(testV3Magic+"ab"), 0600); err != nil {
		t.Fatalf("write short store: %v", err)
	}
	if _, err := GetPwdObj(); err == nil || !strings.Contains(err.Error(), "ciphertext too short") {
		t.Fatalf("expected ciphertext too short, got %v", err)
	}
}

func TestGetPwdObjAfterCheckMaster_UpgradesLegacyStore(t *testing.T) {
	home := withTempHome(t)
	secret := []byte("legacy-store-secret")
	original := model.PwdFile{
		MasterPassword: legacyHash(t, secret),
		SavedPasswords: map[string]string{"site": "value"},
	}
	writeLegacyV2Store(t, secret, original)

	restore := SetReadPasswordStdin(func() ([]byte, error) { return append([]byte(nil), secret...), nil })
	defer restore()

	got, err := GetPwdObjAfterCheckMaster()
	if err != nil {
		t.Fatalf("unlock legacy store: %v", err)
	}
	if got.SavedPasswords["site"] != "value" {
		t.Fatalf("saved passwords lost during upgrade: %v", got.SavedPasswords)
	}
	if hashIterations(t, got.MasterPassword) != pbkdf2Iter || !VerifyMasterPassword(got.MasterPassword, secret) {
		t.Fatalf("returned master hash was not upgraded: %q", got.MasterPassword)
	}
	if iter := readStoreIterations(t, home); iter != pbkdf2Iter {
		t.Fatalf("store iterations after upgrade = %d, want %d", iter, pbkdf2Iter)
	}
	persisted, err := GetPwdObj()
	if err != nil {
		t.Fatalf("read upgraded store: %v", err)
	}
	if persisted.MasterPassword != got.MasterPassword || persisted.SavedPasswords["site"] != "value" {
		t.Fatalf("persisted store does not match upgraded content: %+v", persisted)
	}
}
