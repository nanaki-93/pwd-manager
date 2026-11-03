package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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

func TestReadKeySaltRefusesSymlinkSwappedInAfterCheck(t *testing.T) {
	home := withTempHome(t)
	saltPath := filepath.Join(home, keyDerivationSaltFile)
	if err := os.WriteFile(saltPath, bytes.Repeat([]byte{1}, keyDerivationSaltLen), 0o600); err != nil {
		t.Fatalf("write salt: %v", err)
	}
	target := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(target, bytes.Repeat([]byte{9}, keyDerivationSaltLen), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	prev := openKeyFile
	openKeyFile = func(name string) (*os.File, error) {
		// Simulate the race: replace the checked file with a symlink.
		if err := os.Remove(name); err != nil {
			t.Fatalf("remove salt: %v", err)
		}
		if err := os.Symlink(target, name); err != nil {
			t.Fatalf("symlink salt: %v", err)
		}
		return prev(name)
	}
	t.Cleanup(func() { openKeyFile = prev })

	salt := make([]byte, keyDerivationSaltLen)
	_, loaded, err := readKeySalt(salt)
	if err == nil || loaded || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected swapped-in symlink to be refused, got loaded=%v err=%v", loaded, err)
	}
	if bytes.Contains(salt, []byte{9}) {
		t.Fatal("salt was read through the symlink")
	}
}

func TestWriteKeySaltRefusesSymlinkAndKeepsTarget(t *testing.T) {
	home := withTempHome(t)
	target := filepath.Join(t.TempDir(), "victim")
	orig := []byte("do not overwrite")
	if err := os.WriteFile(target, orig, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(home, keyDerivationSaltFile)); err != nil {
		t.Fatalf("symlink salt: %v", err)
	}
	if err := writeKeySalt(bytes.Repeat([]byte{2}, keyDerivationSaltLen)); err == nil {
		t.Fatal("expected writeKeySalt to refuse a symlinked salt path")
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, orig) {
		t.Fatalf("symlink target changed: %q, %v", got, err)
	}
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
