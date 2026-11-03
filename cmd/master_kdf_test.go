package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

const minAcceptedKDFIterations = 600_000

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

func TestDeriveKeyUsesStrongPBKDF2(t *testing.T) {
	password := []byte("valid-master-secret")
	salt := bytes.Repeat([]byte{0x5c}, keyDerivationSaltLen)
	got, err := deriveKey(password, salt)
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	if bytes.Equal(got, pbkdf2.Key(password, salt, legacyKeyDerivationIterations, encryptionKeyLen, sha256.New)) {
		t.Fatalf("deriveKey still uses the legacy 100,000-iteration work factor")
	}
	want := pbkdf2.Key(password, salt, minAcceptedKDFIterations, encryptionKeyLen, sha256.New)
	if !bytes.Equal(got, want) {
		t.Fatalf("deriveKey output does not match PBKDF2-HMAC-SHA256 at %d iterations", minAcceptedKDFIterations)
	}
}

func TestGenerateKeyStoresKDFParametersMeetingMinimum(t *testing.T) {
	tmpHome := withTempHome(t)
	stubFixedRandSalt(t, 0x3d, nil)
	if err := generateKey([]byte("valid-master-secret")); err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	iter, salt := readStoredSaltParams(t, tmpHome)
	if iter < minAcceptedKDFIterations {
		t.Fatalf("stored PBKDF2 iterations = %d, want >= %d", iter, minAcceptedKDFIterations)
	}
	if !bytes.Equal(salt, bytes.Repeat([]byte{0x3d}, keyDerivationSaltLen)) {
		t.Fatalf("stored salt = %x, want the generated salt", salt)
	}
}

func TestGenerateKeyMigratesLegacySaltFile(t *testing.T) {
	tmpHome := withTempHome(t)
	legacySalt := bytes.Repeat([]byte{0x7e}, keyDerivationSaltLen)
	if err := os.WriteFile(filepath.Join(tmpHome, keyDerivationSaltFile), legacySalt, 0o600); err != nil {
		t.Fatalf("seed legacy salt file: %v", err)
	}
	if err := generateKey([]byte("valid-master-secret")); err != nil {
		t.Fatalf("generateKey with legacy salt file: %v", err)
	}
	iter, salt := readStoredSaltParams(t, tmpHome)
	if iter != keyDerivationIterations || !bytes.Equal(salt, legacySalt) {
		t.Fatalf("migrated salt file = (%d, %x), want (%d, %x)", iter, salt, keyDerivationIterations, legacySalt)
	}
}

func TestParseKeySaltRejectsOutOfRangeIterations(t *testing.T) {
	for _, iter := range []uint32{0, legacyKeyDerivationIterations - 1, maxKeyDerivationIterations + 1} {
		data := binary.BigEndian.AppendUint32([]byte(keySaltMagic), iter)
		data = append(data, make([]byte, keyDerivationSaltLen)...)
		if _, _, err := parseKeySalt(data, keyDerivationSaltLen); err == nil {
			t.Fatalf("parseKeySalt accepted %d iterations", iter)
		}
	}
}
