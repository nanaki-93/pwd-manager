package utils

import (
	"bytes"
	"testing"
)

func TestKDFOverrideHashAndEncryptionParameters(t *testing.T) {
	password := []byte("override-master-secret")
	calls := 0
	var hashSalt []byte
	restore := SetKDFForTesting(func(p, salt []byte, iter, keyLen int) []byte {
		calls++
		if !bytes.Equal(p, password) || iter != pbkdf2Iter || keyLen != derivedKeySize {
			t.Fatalf("incorrect KDF arguments: iterations=%d, keyLen=%d", iter, keyLen)
		}
		if calls == 1 {
			hashSalt = append([]byte(nil), salt...)
			if len(salt) != saltSize {
				t.Fatalf("hash salt length = %d, want %d", len(salt), saltSize)
			}
		} else if calls == 2 && !bytes.Equal(salt, hashSalt) {
			t.Fatal("verification did not use recorded hash salt")
		} else if calls == 3 && !bytes.Equal(salt, []byte("store-salt:enc-v2")) {
			t.Fatal("encryption derivation lost domain separation")
		}
		return bytes.Repeat([]byte{0x61}, keyLen)
	})
	t.Cleanup(restore)
	stored, err := HashMasterPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hashIterations(t, stored) != pbkdf2Iter || !VerifyMasterPassword(stored, password) {
		t.Fatal("hash/verify failed to share override with unscaled recorded iterations")
	}
	got := deriveEncryptionKey(password, []byte("store-salt"), pbkdf2Iter)
	if !bytes.Equal(got, bytes.Repeat([]byte{0x61}, derivedKeySize)) || calls != 3 {
		t.Fatalf("encryption did not use override: calls=%d", calls)
	}
}

func TestKDFOverrideNestedRestore(t *testing.T) {
	password, salt := []byte("restore-secret"), []byte("restore-salt")
	original := kdf(password, salt, legacyPBKDF2Iter, derivedKeySize)
	restoreOuter := SetKDFForTesting(func(_, _ []byte, _, n int) []byte {
		return bytes.Repeat([]byte{0x21}, n)
	})
	t.Cleanup(restoreOuter)
	restoreInner := SetKDFForTesting(func(_, _ []byte, _, n int) []byte {
		return bytes.Repeat([]byte{0x42}, n)
	})
	t.Cleanup(restoreInner)
	if got := kdf(password, salt, legacyPBKDF2Iter, derivedKeySize); !bytes.Equal(got, bytes.Repeat([]byte{0x42}, derivedKeySize)) {
		t.Fatal("inner override inactive")
	}
	restoreInner()
	if got := kdf(password, salt, legacyPBKDF2Iter, derivedKeySize); !bytes.Equal(got, bytes.Repeat([]byte{0x21}, derivedKeySize)) {
		t.Fatal("inner restore did not reinstate outer override")
	}
	restoreOuter()
	if got := kdf(password, salt, legacyPBKDF2Iter, derivedKeySize); !bytes.Equal(got, original) {
		t.Fatal("outer restore did not reinstate original KDF")
	}
}
