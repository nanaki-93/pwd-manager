package cmd

import (
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"testing"

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
// It also scales cmd's own PBKDF2 work down; internal/utils exposes no KDF
// override outside its own tests, so derivations there run at full cost.
// It points HOME and XDG_CACHE_HOME at a temporary directory so daemon tests
// never write the real daemon pidfile.
func TestMain(m *testing.M) {
	clipboardClearer = func(string) error { return nil }
	clipboardReadAll = func() (string, error) { return "", nil }
	pbkdf2Key = fastPBKDF2Key
	os.Exit(runIsolated(m))
}

func runIsolated(m *testing.M) int {
	home, err := os.MkdirTemp("", "pwd-manager-cmd-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create test home: %v\n", err)
		return 1
	}
	defer os.RemoveAll(home)
	for key, value := range map[string]string{"HOME": home, "XDG_CACHE_HOME": filepath.Join(home, ".cache")} {
		if err := os.Setenv(key, value); err != nil {
			fmt.Fprintf(os.Stderr, "set %s: %v\n", key, err)
			return 1
		}
	}
	return m.Run()
}
