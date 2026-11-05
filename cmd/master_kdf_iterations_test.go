package cmd

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

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
