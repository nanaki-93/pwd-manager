package cmd

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"testing"
)

// The cheap test KDF must receive production parameters, not parameters reduced
// by deriveKey itself. Validation must still happen before any expensive work.
func TestDeriveKeyOverridePreservesParametersAndValidation(t *testing.T) {
	previous := pbkdf2Key
	t.Cleanup(func() { pbkdf2Key = previous })
	password := []byte("valid-master-secret")
	salt := []byte("override-test-salt")
	calls := 0
	wantIterations := legacyKeyDerivationIterations
	pbkdf2Key = func(p, s []byte, iter, keyLen int, h func() hash.Hash) []byte {
		calls++
		if !bytes.Equal(p, password) || !bytes.Equal(s, salt) || iter != wantIterations || keyLen != encryptionKeyLen {
			t.Fatalf("incorrect derivation arguments: iterations=%d, keyLen=%d", iter, keyLen)
		}
		if !bytes.Equal(h().Sum(nil), sha256.New().Sum(nil)) {
			t.Fatal("deriveKey did not request SHA256")
		}
		return bytes.Repeat([]byte{0x39}, keyLen)
	}
	for _, iter := range []int{legacyKeyDerivationIterations, keyDerivationIterations, maxKeyDerivationIterations} {
		wantIterations = iter
		got, err := deriveKey(password, salt, iter)
		if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0x39}, encryptionKeyLen)) {
			t.Fatalf("deriveKey(%d) did not use override: %x, %v", iter, got, err)
		}
	}
	before := calls
	for _, iter := range []int{legacyKeyDerivationIterations - 1, maxKeyDerivationIterations + 1} {
		if _, err := deriveKey(password, salt, iter); err == nil {
			t.Errorf("accepted invalid iterations %d", iter)
		}
	}
	if _, err := deriveKey(password, nil, keyDerivationIterations); err == nil {
		t.Error("accepted empty salt")
	}
	if _, err := deriveKey(nil, salt, keyDerivationIterations); err == nil {
		t.Error("accepted empty password")
	}
	if calls != before {
		t.Fatal("invalid input reached KDF override")
	}
}
