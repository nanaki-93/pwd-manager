/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// testKDFScale divides the PBKDF2 work actually computed in tests. Recorded
// iteration counts keep their real values, and distinct counts still derive
// distinct keys, so only the CPU cost of each derivation shrinks.
const testKDFScale = 1000

// fastPBKDF2SHA256 appends the real iteration count to a copy of the salt so
// that counts sharing one scaled bucket still derive distinct keys.
func fastPBKDF2SHA256(password, salt []byte, iter, keyLen int) []byte {
	saltWithIter := binary.BigEndian.AppendUint64(append([]byte(nil), salt...), uint64(iter))
	return pbkdf2SHA256(password, saltWithIter, max(1, iter/testKDFScale), keyLen)
}

func TestFastPBKDF2DistinctIterations(t *testing.T) {
	pw := []byte("password")
	salt := []byte("0123456789abcdef")
	pairs := [][2]int{{1000, 1999}, {600000, 600001}, {1, 999}, {0, 1}, {999, 1000}, {1999, 2000}}
	for _, p := range pairs {
		a := fastPBKDF2SHA256(pw, salt, p[0], 32)
		b := fastPBKDF2SHA256(pw, salt, p[1], 32)
		if len(a) != 32 || len(b) != 32 {
			t.Fatalf("unexpected key length: %d, %d", len(a), len(b))
		}
		if bytes.Equal(a, b) {
			t.Errorf("iter %d and %d derived identical keys", p[0], p[1])
		}
		if !bytes.Equal(a, fastPBKDF2SHA256(pw, salt, p[0], 32)) {
			t.Errorf("iter %d derivation is not deterministic", p[0])
		}
	}
}

func TestFastPBKDF2ScaledIterationBoundaries(t *testing.T) {
	password, salt := []byte("password"), []byte("0123456789abcdef")
	for _, tc := range []struct {
		iter, scaled int
	}{
		{0, 1}, {1, 1}, {999, 1}, {1000, 1}, {1999, 1},
		{2000, 2}, {2999, 2}, {3000, 3}, {600000, 600},
	} {
		// Compare against the primitive at the exact reduced count, avoiding
		// timing assertions while detecting accidental full-cost derivation.
		domainSalt := append([]byte(nil), salt...)
		var count [8]byte
		binary.BigEndian.PutUint64(count[:], uint64(tc.iter))
		domainSalt = append(domainSalt, count[:]...)
		want := pbkdf2SHA256(password, domainSalt, tc.scaled, 32)
		if got := fastPBKDF2SHA256(password, salt, tc.iter, 32); !bytes.Equal(got, want) {
			t.Errorf("iter %d: output differs from PBKDF2 with %d scaled iterations", tc.iter, tc.scaled)
		}
	}
}

func TestFastPBKDF2DeterministicKeyLengths(t *testing.T) {
	for _, keyLen := range []int{0, 1, 31, 32, 33, 64, 65} {
		password, salt := []byte("password"), []byte("0123456789abcdef")
		got := fastPBKDF2SHA256(password, salt, 2000, keyLen)
		if len(got) != keyLen {
			t.Fatalf("keyLen %d: got length %d", keyLen, len(got))
		}
		if again := fastPBKDF2SHA256(password, salt, 2000, keyLen); !bytes.Equal(got, again) {
			t.Errorf("keyLen %d: repeated derivation differs", keyLen)
		}
	}
}

// TestMain scales PBKDF2 work down, which dominated the package's test time.
// pbkdf2SHA256 itself is still checked against x/crypto/pbkdf2 directly.
func TestMain(m *testing.M) {
	SetKDFForTesting(fastPBKDF2SHA256)
	os.Exit(m.Run())
}
