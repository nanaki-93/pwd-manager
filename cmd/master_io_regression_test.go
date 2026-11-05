package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
