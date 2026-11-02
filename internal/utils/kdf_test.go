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

const minRecommendedPBKDF2Iter = 600000

func legacyHash(t *testing.T, password []byte) string {
	t.Helper()
	salt := bytes.Repeat([]byte{0x42}, saltSize)
	dk := pbkdf2SHA256(password, salt, legacyPBKDF2Iter, derivedKeySize)
	return fmt.Sprintf("%s%s$%s", hashPrefix, hex.EncodeToString(salt), hex.EncodeToString(dk))
}

func writeLegacyV2Store(t *testing.T, secret []byte, content model.PwdFile) {
	t.Helper()
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	salt := bytes.Repeat([]byte{0x24}, saltSize)
	key := deriveEncryptionKey(secret, salt, legacyPBKDF2Iter)
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
	if !bytes.HasPrefix(raw, []byte(v3Magic)) || len(raw) < len(v3Magic)+iterFieldSize {
		t.Fatalf("store header does not record KDF parameters: %q", raw[:min(len(raw), 8)])
	}
	return int(binary.BigEndian.Uint32(raw[len(v3Magic):]))
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
	if !hashNeedsUpgrade(stored) {
		t.Fatalf("legacy hash should be flagged for upgrade")
	}
	rest := strings.TrimPrefix(stored, hashPrefix)
	for _, iter := range []string{"1", "99999", "4294967296", "-5"} {
		if VerifyMasterPassword(hashPrefix+iter+"$"+rest, pwd) {
			t.Errorf("hash with out-of-range iteration count %s accepted", iter)
		}
	}
}

func TestDecryptV3_RejectsOutOfRangeIterations(t *testing.T) {
	SetMasterKey([]byte("bounds-secret"))
	defer SetMasterKey(nil)
	payload := make([]byte, iterFieldSize+saltSize+32)
	binary.BigEndian.PutUint32(payload, 0xFFFFFFFF)
	if _, _, err := decryptV3(payload); err == nil || !strings.Contains(err.Error(), "unsupported PBKDF2 iteration count") {
		t.Fatalf("expected out-of-range iteration error, got %v", err)
	}
	if _, _, err := decryptV3(payload[:2]); err == nil || !strings.Contains(err.Error(), "ciphertext too short") {
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

	restore := SetReadPasswordStdin(func() ([]byte, error) { return secret, nil })
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
