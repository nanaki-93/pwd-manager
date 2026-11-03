/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"os"
	"testing"
)

// testKDFScale divides the PBKDF2 work actually computed in tests. Recorded
// iteration counts keep their real values, and distinct counts still derive
// distinct keys, so only the CPU cost of each derivation shrinks.
const testKDFScale = 1000

func fastPBKDF2SHA256(password, salt []byte, iter, keyLen int) []byte {
	return pbkdf2SHA256(password, salt, max(1, iter/testKDFScale), keyLen)
}

// TestMain scales PBKDF2 work down, which dominated the package's test time.
// pbkdf2SHA256 itself is still checked against x/crypto/pbkdf2 directly.
func TestMain(m *testing.M) {
	SetKDFForTesting(fastPBKDF2SHA256)
	os.Exit(m.Run())
}
