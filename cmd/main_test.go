package cmd

import (
	"os"
	"testing"
)

// TestMain stops tests from blocking on, or touching, the real clipboard when
// `add --copy` schedules clearing; tests that cover clearing stub it themselves.
func TestMain(m *testing.M) {
	clipboardClearer = func(string) error { return nil }
	clipboardReadAll = func() (string, error) { return "", nil }
	os.Exit(m.Run())
}
