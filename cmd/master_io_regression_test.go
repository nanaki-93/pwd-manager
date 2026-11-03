package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func TestGenerateKeyUsesHomeWithoutChangingWorkingDirectory(t *testing.T) {
	home := withTempHome(t)
	start := chdirToEmptyDir(t)
	stubFixedRandSalt(t, 0x36, nil)
	legacy := filepath.Join(home, utils.PwdFileKey)
	if err := os.WriteFile(legacy, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := generateKey([]byte("valid-master-secret")); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	wantInfo, err := os.Stat(start)
	if err != nil {
		t.Fatal(err)
	}
	gotInfo, err := os.Stat(wd)
	if err != nil || !os.SameFile(wantInfo, gotInfo) {
		t.Fatalf("working directory changed: %q, %v", wd, err)
	}
	assertDirEmpty(t, start)
	_, salt := readStoredSaltParams(t, home)
	if !bytes.Equal(salt, bytes.Repeat([]byte{0x36}, keyDerivationSaltLen)) {
		t.Fatal("salt not persisted in home")
	}
	if _, err := os.Lstat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("home legacy file not removed: %v", err)
	}
}

func TestReadKeySaltWrapsOpenFailureWithoutChangingOutput(t *testing.T) {
	home := withTempHome(t)
	if err := os.WriteFile(filepath.Join(home, keyDerivationSaltFile), bytes.Repeat([]byte{1}, keyDerivationSaltLen), 0o600); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("injected open failure")
	original := openKeyFile
	openKeyFile = func(string) (*os.File, error) { return nil, cause }
	t.Cleanup(func() { openKeyFile = original })
	salt := bytes.Repeat([]byte{7}, keyDerivationSaltLen)
	iterations, loaded, err := readKeySalt(salt)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "open salt file:") {
		t.Fatalf("missing wrapped operation context: %v", err)
	}
	if loaded || iterations != 0 || !bytes.Equal(salt, bytes.Repeat([]byte{7}, keyDerivationSaltLen)) {
		t.Fatal("failed read changed caller output")
	}
}

func TestWriteKeySaltWrapsTemporaryFileFailure(t *testing.T) {
	home := withTempHome(t)
	missingHome := filepath.Join(home, "missing")
	original := userHomeDir
	userHomeDir = func() (string, error) { return missingHome, nil }
	t.Cleanup(func() { userHomeDir = original })
	err := writeKeySalt(bytes.Repeat([]byte{2}, keyDerivationSaltLen))
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "write salt file: create temp file:") {
		t.Fatalf("missing wrapped salt persistence context: %v", err)
	}
	assertDirEmpty(t, home)
}
