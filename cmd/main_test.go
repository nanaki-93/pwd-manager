package cmd

import (
	"crypto/sha256"
	"hash"
	"os"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/utils"
	"golang.org/x/crypto/pbkdf2"
)

// testKDFScale divides the PBKDF2 work actually computed in tests. Recorded
// iteration counts keep their real values, and distinct counts still derive
// distinct keys, so only the CPU cost of each derivation shrinks.
const testKDFScale = 1000

func scaledIterations(iter int) int {
	return max(1, iter/testKDFScale)
}

// fastPBKDF2Key is PBKDF2 at a scaled-down work factor for tests.
func fastPBKDF2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	return pbkdf2.Key(password, salt, scaledIterations(iter), keyLen, h)
}

// useRealKDF makes deriveKey compute PBKDF2 at its full work factor for one
// test, for tests that compare its output with an independent derivation.
func useRealKDF(t *testing.T) {
	t.Helper()
	prev := pbkdf2Key
	pbkdf2Key = pbkdf2.Key
	t.Cleanup(func() { pbkdf2Key = prev })
}

// TestMain stops tests from blocking on, or touching, the real clipboard when
// `add --copy` schedules clearing; tests that cover clearing stub it themselves.
// It also scales PBKDF2 work down, which dominated the package's test time.
func TestMain(m *testing.M) {
	clipboardClearer = func(string) error { return nil }
	clipboardReadAll = func() (string, error) { return "", nil }
	pbkdf2Key = fastPBKDF2Key
	utils.SetKDFForTesting(func(password, salt []byte, iter, keyLen int) []byte {
		return fastPBKDF2Key(password, salt, iter, keyLen, sha256.New)
	})
	os.Exit(m.Run())
}
