package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func withTempHome(t *testing.T) string {
	t.Helper()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origWd)
	})

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	return tmpHome
}

func TestGenerateKeyAbortsOnRandError(t *testing.T) {
	tmpHome := withTempHome(t)

	origRandRead := randRead
	defer func() {
		randRead = origRandRead
	}()

	randRead = func(r io.Reader, buf []byte) (int, error) {
		return 0, errors.New("rng failure")
	}

	err := generateKey()
	if err == nil {
		t.Fatalf("expected error when random number generator fails, got nil")
	}

	if _, statErr := os.Stat(filepath.Join(tmpHome, utils.PwdFileKey)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected key file not to be written on rng error, stat err: %v", statErr)
	}
}

func TestGenerateKeyReturnsErrorOnWriteFailure(t *testing.T) {
	tmpHome := withTempHome(t)

	// Create a directory at the key file path so os.WriteFile fails.
	if err := os.Mkdir(filepath.Join(tmpHome, utils.PwdFileKey), 0700); err != nil {
		t.Fatalf("failed to create directory at key path: %v", err)
	}

	if err := generateKey(); err == nil {
		t.Fatalf("expected error when writing key file fails, got nil")
	}
}

func TestGenerateKeyWritesExpectedKeyOnSuccess(t *testing.T) {
	tmpHome := withTempHome(t)

	origRandRead := randRead
	defer func() {
		randRead = origRandRead
	}()

	expectedKey := bytes.Repeat([]byte{0xab}, 32)
	randRead = func(r io.Reader, buf []byte) (int, error) {
		copy(buf, expectedKey)
		return len(buf), nil
	}

	if err := generateKey(); err != nil {
		t.Fatalf("expected nil error from generateKey, got: %v", err)
	}

	gotKey, err := os.ReadFile(filepath.Join(tmpHome, utils.PwdFileKey))
	if err != nil {
		t.Fatalf("failed to read generated key file: %v", err)
	}
	if !bytes.Equal(gotKey, expectedKey) {
		t.Fatalf("generated key mismatch: got %x, want %x", gotKey, expectedKey)
	}
}

func TestExecMasterCmdDoesNotOverwriteKeyOnCorruptFile(t *testing.T) {
	tmpHome := withTempHome(t)

	existingKey := bytes.Repeat([]byte{0x42}, 32)
	keyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	if err := os.WriteFile(keyPath, existingKey, 0700); err != nil {
		t.Fatalf("failed to write existing key: %v", err)
	}

	// Write a valid-length nonce + invalid ciphertext so readPwdFile returns non-JSON plaintext,
	// causing GetPwdObj to return a json.Unmarshal error (not os.ErrNotExist).
	pwdPath := filepath.Join(tmpHome, utils.PwdFileName)
	corruptContent := bytes.Repeat([]byte{0x99}, 32)
	if err := os.WriteFile(pwdPath, corruptContent, 0700); err != nil {
		t.Fatalf("failed to write corrupt password file: %v", err)
	}

	execMasterCmd(masterCmd, nil)

	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}
	if !bytes.Equal(gotKey, existingKey) {
		t.Fatalf("existing key was overwritten on non-ErrNotExist load failure")
	}

	gotPwdFile, err := os.ReadFile(pwdPath)
	if err != nil {
		t.Fatalf("failed to read password file: %v", err)
	}
	if !bytes.Equal(gotPwdFile, corruptContent) {
		t.Fatalf("existing password file was overwritten on non-ErrNotExist load failure")
	}
}

func TestExecMasterCmdAbortsWhenKeyGenerationFails(t *testing.T) {
	tmpHome := withTempHome(t)

	origRandRead := randRead
	defer func() {
		randRead = origRandRead
	}()

	randRead = func(r io.Reader, buf []byte) (int, error) {
		return 0, errors.New("entropy exhausted")
	}

	execMasterCmd(masterCmd, nil)

	if _, err := os.Stat(filepath.Join(tmpHome, utils.PwdFileKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no key file when key generation fails, got stat err: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no password file when key generation fails, got stat err: %v", err)
	}
}

func TestGetPwdObjAfterCheckMasterPropagatesLoadError(t *testing.T) {
	_ = withTempHome(t)

	_, err := utils.GetPwdObjAfterCheckMaster()
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist when password file does not exist, got: %v", err)
	}
}

func TestGetPwdObjAfterCheckMasterRejectsMismatchedMasterPassword(t *testing.T) {
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) != 0 {
		t.Skip("skipping test when stdin is a terminal device")
	}

	tmpHome := withTempHome(t)

	key := bytes.Repeat([]byte{0x11}, 32)
	if err := os.WriteFile(filepath.Join(tmpHome, utils.PwdFileKey), key, 0700); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	seeded := model.PwdFile{
		MasterPassword: "non-empty-master-secret",
	}
	utils.SaveFile(seeded, nil)

	got, err := utils.GetPwdObjAfterCheckMaster()
	if err == nil {
		t.Fatalf("expected error when master password verification fails, got nil (obj: %+v)", got)
	}
	if got.MasterPassword != "" {
		t.Fatalf("expected empty PwdFile on verification failure, got: %+v", got)
	}
}
