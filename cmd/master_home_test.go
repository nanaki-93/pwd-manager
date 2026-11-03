package cmd

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// chdirToEmptyDir makes a fresh empty directory the working directory for the
// test and restores the previous one afterwards.
func chdirToEmptyDir(t *testing.T) string {
	t.Helper()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	startDir := t.TempDir()
	if err := os.Chdir(startDir); err != nil {
		t.Fatalf("chdir to start dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWd) })
	return startDir
}

func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read start dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files in starting directory, found %d (first %q)", len(entries), entries[0].Name())
	}
}

func TestGenerateKeyFailsWithoutTouchingWorkingDirWhenHomeLookupFails(t *testing.T) {
	withTempHome(t)
	startDir := chdirToEmptyDir(t)
	// Both the injected resolver and the environment fail to give a home.
	t.Setenv("HOME", "")
	homeErr := errors.New("no home for you")
	prev := userHomeDir
	userHomeDir = func() (string, error) { return "", homeErr }
	t.Cleanup(func() { userHomeDir = prev })

	err := generateKey([]byte("valid-master-secret"))
	if !errors.Is(err, homeErr) {
		t.Fatalf("expected generateKey to return the home lookup error, got: %v", err)
	}
	assertDirEmpty(t, startDir)
}

func TestGenerateKeyRejectsRelativeHomeDir(t *testing.T) {
	withTempHome(t)
	startDir := chdirToEmptyDir(t)
	t.Setenv("HOME", ".")
	prev := userHomeDir
	userHomeDir = func() (string, error) { return ".", nil }
	t.Cleanup(func() { userHomeDir = prev })

	err := generateKey([]byte("valid-master-secret"))
	if err == nil || !strings.Contains(err.Error(), "not an absolute path") {
		t.Fatalf("expected relative home dir to be rejected, got: %v", err)
	}
	assertDirEmpty(t, startDir)
}
