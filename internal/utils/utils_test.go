/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestHashMasterPassword(t *testing.T) {
	password := []byte("master-password-test")
	hash1, err := HashMasterPassword(password)
	if err != nil {
		t.Fatalf("HashMasterPassword failed: %v", err)
	}
	if !strings.HasPrefix(hash1, hashPrefix) {
		t.Fatalf("HashMasterPassword returned hash without prefix: %s", hash1)
	}

	hash2, err := HashMasterPassword(password)
	if err != nil {
		t.Fatalf("HashMasterPassword failed: %v", err)
	}
	if hash1 == hash2 {
		t.Fatalf("HashMasterPassword should generate unique salts, got identical hashes: %s", hash1)
	}

	if !VerifyMasterPassword(hash1, password) {
		t.Fatalf("VerifyMasterPassword failed for generated hash1")
	}
	if !VerifyMasterPassword(hash2, password) {
		t.Fatalf("VerifyMasterPassword failed for generated hash2")
	}
}

func TestVerifyMasterPassword_PBKDF2(t *testing.T) {
	password := []byte("secret-master-password")
	hashed, err := HashMasterPassword(password)
	if err != nil {
		t.Fatalf("HashMasterPassword failed: %v", err)
	}

	if !VerifyMasterPassword(hashed, password) {
		t.Errorf("VerifyMasterPassword(%q, %q) = false, want true", hashed, password)
	}
	if VerifyMasterPassword(hashed, []byte("wrong-password")) {
		t.Errorf("VerifyMasterPassword with wrong password returned true, want false")
	}
}

func TestVerifyMasterPassword_LegacyFallback(t *testing.T) {
	rawDigestHex := fmt.Sprintf("%x", sha256.Sum256([]byte("legacy-secret-password")))
	tests := []struct {
		name      string
		stored    string
		candidate []byte
		want      bool
	}{
		{
			name:      "exact match on unprefixed plaintext password is rejected",
			stored:    "legacy-secret-password",
			candidate: []byte("legacy-secret-password"),
			want:      false,
		},
		{
			name:      "unprefixed single-pass sha256 digest is rejected",
			stored:    rawDigestHex,
			candidate: []byte("legacy-secret-password"),
			want:      false,
		},
		{
			name:      "unprefixed candidate matching digest string is rejected",
			stored:    rawDigestHex,
			candidate: []byte(rawDigestHex),
			want:      false,
		},
		{
			name:      "mismatched candidate on legacy plaintext password",
			stored:    "legacy-secret-password",
			candidate: []byte("different-password"),
			want:      false,
		},
		{
			name:      "empty stored password returns false",
			stored:    "",
			candidate: []byte("candidate"),
			want:      false,
		},
		{
			name:      "empty candidate with legacy stored returns false",
			stored:    "legacy-secret-password",
			candidate: []byte(""),
			want:      false,
		},
		{
			name:      "both stored and candidate empty returns false",
			stored:    "",
			candidate: []byte(""),
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyMasterPassword(tc.stored, tc.candidate)
			if got != tc.want {
				t.Errorf("VerifyMasterPassword(%q, %q) = %v, want %v", tc.stored, tc.candidate, got, tc.want)
			}
		})
	}
}

func TestVerifyMasterPassword_RejectsUnprefixedStrings(t *testing.T) {
	TestVerifyMasterPassword_LegacyFallback(t)
}

func TestPromptPasswordErr_NormalizesNilSlice(t *testing.T) {
	restore := SetReadPasswordStdin(func() ([]byte, error) {
		return nil, nil
	})
	defer restore()

	got, err := PromptPasswordErr("Enter password:")
	if err != nil {
		t.Fatalf("expected nil error from PromptPasswordErr, got %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil empty byte slice when reader returns (nil, nil), got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected empty byte slice, got %q", got)
	}
}

func TestVerifyMasterPassword_MalformedPBKDF2(t *testing.T) {
	password := []byte("secret-master-password")
	tests := []struct {
		name   string
		stored string
	}{
		{
			name:   "missing delimiter",
			stored: hashPrefix + "invalidsaltandkey",
		},
		{
			name:   "extra delimiter",
			stored: hashPrefix + "aa$bb$cc",
		},
		{
			name:   "empty salt part",
			stored: hashPrefix + "$aabbcc",
		},
		{
			name:   "empty dk part",
			stored: hashPrefix + "aabbcc$",
		},
		{
			name:   "invalid hex characters",
			stored: hashPrefix + "zzzz$zzzz",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyMasterPassword(tc.stored, password) {
				t.Errorf("VerifyMasterPassword(%q, %q) = true, want false", tc.stored, password)
			}
		})
	}
}

func TestVerifyMasterPassword_SingleByteDerivedKey(t *testing.T) {
	password := []byte("secret-master-password")
	salt := make([]byte, saltSize)
	oneByteDK := pbkdf2SHA256(password, salt, pbkdf2Iter, 1)
	singleByteRecord := fmt.Sprintf("%s%s$%s", hashPrefix, hex.EncodeToString(salt), hex.EncodeToString(oneByteDK))
	if VerifyMasterPassword(singleByteRecord, password) {
		t.Errorf("VerifyMasterPassword(%q, %q) = true, want false (accepted single-byte derived key)", singleByteRecord, password)
	}

	truncatedSalt := fmt.Sprintf("%s%s$%s", hashPrefix, "00", hex.EncodeToString(make([]byte, derivedKeySize)))
	if VerifyMasterPassword(truncatedSalt, password) {
		t.Errorf("VerifyMasterPassword(%q, %q) = true, want false (accepted truncated salt)", truncatedSalt, password)
	}
}

func TestPBKDF2SHA256_Equivalence(t *testing.T) {
	password := []byte("test-equivalence-password")
	salt := []byte("1234567890123456")
	iter := 100
	keyLen := 32
	got := pbkdf2SHA256(password, salt, iter, keyLen)
	wantCrypto := pbkdf2.Key(password, salt, iter, keyLen, sha256.New)
	if !bytes.Equal(got, wantCrypto) {
		t.Errorf("pbkdf2SHA256 output does not match x/crypto/pbkdf2")
	}
	wantReused := pbkdf2SHA256ReusedHMAC(password, salt, iter, keyLen)
	if !bytes.Equal(got, wantReused) {
		t.Errorf("pbkdf2SHA256 output does not match pbkdf2SHA256ReusedHMAC")
	}
}

func pbkdf2SHA256ReusedHMAC(password, salt []byte, iter, keyLen int) []byte {
	if keyLen <= 0 {
		return nil
	}
	mac := hmac.New(sha256.New, password)
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)
	var intBuf [4]byte
	saltBlock := make([]byte, len(salt)+4)
	copy(saltBlock, salt)
	u := make([]byte, hashLen)
	uBuf := make([]byte, hashLen)
	t := make([]byte, hashLen)

	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(intBuf[:], uint32(block))
		copy(saltBlock[len(salt):], intBuf[:])

		mac.Reset()
		mac.Write(saltBlock)
		u = mac.Sum(u[:0])
		copy(t, u)

		for i := 2; i <= iter; i++ {
			mac.Reset()
			mac.Write(u)
			uBuf = mac.Sum(uBuf[:0])
			for j := range t {
				t[j] ^= uBuf[j]
			}
			u, uBuf = uBuf, u
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func BenchmarkPBKDF2SHA256(b *testing.B) {
	password := []byte("benchmark-password")
	salt := make([]byte, saltSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pbkdf2SHA256(password, salt, 1000, derivedKeySize)
	}
}

func BenchmarkPBKDF2SHA256_ReusedHMAC(b *testing.B) {
	password := []byte("benchmark-password")
	salt := make([]byte, saltSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pbkdf2SHA256ReusedHMAC(password, salt, 1000, derivedKeySize)
	}
}

func BenchmarkPBKDF2SHA256_CryptoPBKDF2(b *testing.B) {
	password := []byte("benchmark-password")
	salt := make([]byte, saltSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pbkdf2.Key(password, salt, 1000, derivedKeySize, sha256.New)
	}
}
