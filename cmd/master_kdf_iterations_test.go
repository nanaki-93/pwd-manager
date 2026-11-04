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
	"golang.org/x/crypto/pbkdf2"
)

// assertGenerateKeyReproducesRecordedKey seeds saltData, encrypts a store with
// the key PBKDF2 gives at iterations, and checks that generateKey reproduces
// that key and leaves the salt file as it was.
func assertGenerateKeyReproducesRecordedKey(t *testing.T, saltData, salt []byte, iterations int) {
	t.Helper()
	tmpHome := withTempHome(t)
	t.Cleanup(func() { utils.SetMasterKey(nil) })
	saltPath := filepath.Join(tmpHome, keyDerivationSaltFile)
	if err := os.WriteFile(saltPath, saltData, 0o600); err != nil {
		t.Fatalf("seed salt file: %v", err)
	}
	password := []byte("valid-master-secret")
	utils.SetMasterKey(pbkdf2Key(password, salt, iterations, encryptionKeyLen, sha256.New))
	original := model.PwdFile{MasterPassword: hashFixture(t, string(password)), SavedPasswords: map[string]string{"mail": "c2VjcmV0"}}
	if err := utils.SaveFileErr(original, nil); err != nil {
		t.Fatalf("write fixture store: %v", err)
	}
	utils.SetMasterKey(nil)

	if err := generateKey(password); err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if got, err := os.ReadFile(saltPath); err != nil || !bytes.Equal(got, saltData) {
		t.Fatalf("salt file rewritten by generateKey (err=%v): got %x, want %x", err, got, saltData)
	}
	utils.SetMasterKey(nil)
	if err := generateKey(password); err != nil {
		t.Fatalf("second generateKey: %v", err)
	}
	loaded, err := utils.GetPwdObj()
	if err != nil || loaded.SavedPasswords["mail"] != "c2VjcmV0" {
		t.Fatalf("store unreadable with key derived at recorded %d iterations (err=%v)", iterations, err)
	}
}

func TestGenerateKeyUsesLegacyIterationsForRawSalt(t *testing.T) {
	salt := bytes.Repeat([]byte{0x6a}, keyDerivationSaltLen)
	assertGenerateKeyReproducesRecordedKey(t, salt, salt, legacyKeyDerivationIterations)
}

func TestGenerateKeyUsesRecordedHeaderIterations(t *testing.T) {
	const recorded = 200_000
	salt := bytes.Repeat([]byte{0x4b}, keyDerivationSaltLen)
	data := binary.BigEndian.AppendUint32([]byte(keySaltMagic), recorded)
	data = append(data, salt...)
	assertGenerateKeyReproducesRecordedKey(t, data, salt, recorded)
}

func TestDeriveKeyUsesGivenIterations(t *testing.T) {
	useRealKDF(t)
	password := []byte("valid-master-secret")
	salt := bytes.Repeat([]byte{0x19}, keyDerivationSaltLen)
	got, err := deriveKey(password, salt, legacyKeyDerivationIterations)
	if err != nil || !bytes.Equal(got, pbkdf2.Key(password, salt, legacyKeyDerivationIterations, encryptionKeyLen, sha256.New)) {
		t.Fatalf("deriveKey did not use the given iteration count (err=%v)", err)
	}
	for _, iter := range []int{0, legacyKeyDerivationIterations - 1, maxKeyDerivationIterations + 1} {
		if _, err := deriveKey(password, salt, iter); err == nil {
			t.Fatalf("deriveKey accepted %d iterations", iter)
		}
	}
}
