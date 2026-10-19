/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"strings"
	"testing"
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
	tests := []struct {
		name      string
		stored    string
		candidate []byte
		want      bool
	}{
		{
			name:      "exact match on legacy plaintext password",
			stored:    "legacy-secret-password",
			candidate: []byte("legacy-secret-password"),
			want:      true,
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
