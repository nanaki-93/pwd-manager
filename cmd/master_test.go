package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func init() {
	utils.SetExitFunc(func(int) {})
}

func withTempHome(t *testing.T) string {
	t.Helper()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	revExit := utils.SetExitFunc(func(int) {})
	t.Cleanup(func() {
		revExit()
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

	// Write a valid-length nonce + invalid ciphertext so readPwdFile returns an error.
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

func TestExecMasterCmdInitializesKeyAndHashedPassword(t *testing.T) {
	_ = withTempHome(t)
	stubPasswordSequence(t, "first-time-secret")

	execMasterCmd(masterCmd, nil)

	loaded, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("expected GetPwdObj to succeed after initial master command, got: %v", err)
	}
	if !strings.HasPrefix(loaded.MasterPassword, "pbkdf2-sha256$") {
		t.Fatalf("expected salted PBKDF2 hash prefix, got %q", loaded.MasterPassword)
	}
	if !utils.VerifyMasterPassword(loaded.MasterPassword, []byte("first-time-secret")) {
		t.Fatalf("expected saved master password hash to verify against initial secret")
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

	hashed, err := utils.HashMasterPassword([]byte("non-empty-master-secret"))
	if err != nil {
		t.Fatalf("failed to hash master password: %v", err)
	}
	seeded := model.PwdFile{
		MasterPassword: hashed,
	}
	utils.SaveFile(seeded, nil)

	got, err := utils.GetPwdObjAfterCheckMaster()
	if err == nil {
		t.Fatalf("expected error when master password verification fails, got nil (obj: %+v)", got)
	}
	if got.MasterPassword != "" {
		t.Fatalf("expected empty PwdFile on verification failure, got: %+v", got)
	}

	restoreReader := utils.SetReadPasswordStdin(func() ([]byte, error) {
		return []byte("non-empty-master-secret"), nil
	})
	defer restoreReader()

	gotValid, err := utils.GetPwdObjAfterCheckMaster()
	if err != nil {
		t.Fatalf("expected nil error when master password matches, got: %v", err)
	}
	if gotValid.MasterPassword != hashed {
		t.Fatalf("expected loaded MasterPassword %q, got %q", hashed, gotValid.MasterPassword)
	}
}

func TestHashAndVerifyMasterPassword(t *testing.T) {
	raw := "super-secret-master-password"
	hashed, err := utils.HashMasterPassword([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error hashing password: %v", err)
	}
	if hashed == raw || strings.Contains(hashed, raw) {
		t.Fatalf("expected hashed password not to contain raw secret, got: %q", hashed)
	}
	if !utils.VerifyMasterPassword(hashed, []byte(raw)) {
		t.Fatalf("expected VerifyMasterPassword to succeed for matching password")
	}
	if utils.VerifyMasterPassword(hashed, []byte("wrong-password")) {
		t.Fatalf("expected VerifyMasterPassword to fail for wrong password")
	}
}

func TestVerifyMasterPasswordBoundariesAndLegacyFallback(t *testing.T) {
	raw := []byte("correct-horse-battery-staple")
	hash1, err := utils.HashMasterPassword(raw)
	if err != nil {
		t.Fatalf("unexpected error hashing password (1): %v", err)
	}
	hash2, err := utils.HashMasterPassword(raw)
	if err != nil {
		t.Fatalf("unexpected error hashing password (2): %v", err)
	}
	if hash1 == hash2 {
		t.Fatalf("expected random salt to produce distinct hashes for identical passwords, got %q", hash1)
	}
	if !utils.VerifyMasterPassword(hash1, raw) || !utils.VerifyMasterPassword(hash2, raw) {
		t.Fatalf("expected both salted hashes to verify against original password")
	}

	invalidStored := []string{
		"",
		"pbkdf2-sha256$",
		"pbkdf2-sha256$onlysalt",
		"pbkdf2-sha256$a$b$c",
		"pbkdf2-sha256$not-hex$abcd",
		"pbkdf2-sha256$$abcd",
		"pbkdf2-sha256$abcd$not-hex",
		"pbkdf2-sha256$abcd$",
		"legacy-plaintext",
	}
	for _, stored := range invalidStored {
		if utils.VerifyMasterPassword(stored, raw) {
			t.Fatalf("expected VerifyMasterPassword(%q) to return false", stored)
		}
		if utils.VerifyMasterPassword(stored, nil) {
			t.Fatalf("expected VerifyMasterPassword(%q, nil) to return false", stored)
		}
	}

	if utils.VerifyMasterPassword("legacy-plaintext", []byte("legacy-plaintext")) {
		t.Fatalf("expected unprefixed plaintext verification to be rejected")
	}
}

func TestSaveFileReturnsErrorWhenKeyMissing(t *testing.T) {
	tmpHome := withTempHome(t)

	err := utils.SaveFileErr(model.PwdFile{MasterPassword: "hash"}, nil)
	if err == nil {
		t.Fatalf("expected SaveFileErr to return error when key file is missing")
	}
	if _, statErr := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected encrypted file not to be created when encryption fails, stat err: %v", statErr)
	}
}

func TestSaveFileRejectsUpstreamAndCipherErrors(t *testing.T) {
	tmpHome := withTempHome(t)

	exitCount := 0
	restore := utils.SetExitFunc(func(code int) {
		if code != 0 {
			exitCount++
		}
	})
	defer restore()

	inErr := errors.New("upstream failure")
	if err := utils.SaveFileErr(model.PwdFile{MasterPassword: "hash"}, inErr); !errors.Is(err, inErr) {
		t.Fatalf("expected SaveFileErr to return input error %v, got %v", inErr, err)
	}
	utils.SaveFile(model.PwdFile{MasterPassword: "hash"}, inErr)
	if exitCount != 1 {
		t.Fatalf("expected ManageErrorAndExit to be triggered once for input error, got %d", exitCount)
	}

	keyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	pwdPath := filepath.Join(tmpHome, utils.PwdFileName)
	if err := os.WriteFile(keyPath, []byte("short"), 0700); err != nil {
		t.Fatalf("failed to write short key: %v", err)
	}
	if err := utils.SaveFileErr(model.PwdFile{MasterPassword: "hash"}, nil); err == nil {
		t.Fatalf("expected SaveFileErr to fail with invalid AES key size")
	}
	if _, statErr := os.Stat(pwdPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected password file not to exist after cipher init failure, got: %v", statErr)
	}
}

func TestSaveFileAndGetPwdObjStorageAndRoundTrip(t *testing.T) {
	tmpHome := withTempHome(t)
	keyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	pwdPath := filepath.Join(tmpHome, utils.PwdFileName)

	validKey := bytes.Repeat([]byte{0x33}, 32)
	if err := os.WriteFile(keyPath, validKey, 0700); err != nil {
		t.Fatalf("failed to write valid key: %v", err)
	}
	if err := os.WriteFile(pwdPath, []byte("tiny"), 0700); err != nil {
		t.Fatalf("failed to write truncated ciphertext: %v", err)
	}
	if _, err := utils.GetPwdObj(); err == nil {
		t.Fatalf("expected GetPwdObj to return error on truncated ciphertext shorter than nonce")
	}
	_ = os.Remove(pwdPath)

	if err := os.Mkdir(pwdPath, 0700); err != nil {
		t.Fatalf("failed to create directory at password file path: %v", err)
	}
	if err := utils.SaveFileErr(model.PwdFile{MasterPassword: "hash"}, nil); err == nil {
		t.Fatalf("expected SaveFileErr to return error when writing encrypted file fails")
	}
	if err := os.Remove(pwdPath); err != nil {
		t.Fatalf("failed to remove directory at password file path: %v", err)
	}

	expectedHash, err := utils.HashMasterPassword([]byte("round-trip-secret"))
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	utils.SaveFile(model.PwdFile{MasterPassword: expectedHash}, nil)
	loaded, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("expected GetPwdObj to succeed after SaveFile, got: %v", err)
	}
	if loaded.MasterPassword != expectedHash {
		t.Fatalf("loaded MasterPassword mismatch: got %q, want %q", loaded.MasterPassword, expectedHash)
	}
}

func stubPasswordSequence(t *testing.T, inputs ...string) {
	t.Helper()
	idx := 0
	restore := utils.SetReadPasswordStdin(func() ([]byte, error) {
		if idx >= len(inputs) {
			return nil, errors.New("unexpected password prompt")
		}
		p := []byte(inputs[idx])
		idx++
		return p, nil
	})
	t.Cleanup(restore)
}

func assertWeakPasswordRejected(t *testing.T, tmpHome, candidate, wantErr string) {
	t.Helper()
	err := validateMasterPassword([]byte(candidate))
	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("validateMasterPassword(%q) = %v, want error containing %q", candidate, err, wantErr)
	}

	stubPasswordSequence(t, candidate)
	exitCalled := false
	restoreExit := utils.SetExitFunc(func(code int) {
		if code != 0 {
			exitCalled = true
		}
	})
	savePassword(model.PwdFile{})
	restoreExit()

	if !exitCalled {
		t.Fatalf("expected ManageErrorAndExit to be called for weak master password %q", candidate)
	}
	if _, statErr := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected password file not to be written for weak password %q, stat err: %v", candidate, statErr)
	}
}

func TestSavePasswordRejectsEmptyAndWeakInputs(t *testing.T) {
	tmpHome := withTempHome(t)
	keyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x77}, 32), 0700); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	tests := []struct {
		name, candidate, wantErr string
	}{
		{"empty input", "", "master password cannot be empty"},
		{"whitespace only input", "   \t\n  ", "master password cannot be empty"},
		{"short input", "short", "at least 8 characters"},
		{"seven character boundary input", "1234567", "at least 8 characters"},
		{"padded short input", "  1234567  ", "at least 8 characters"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertWeakPasswordRejected(t, tmpHome, tc.candidate, tc.wantErr)
		})
	}

	if err := validateMasterPassword([]byte("12345678")); err != nil {
		t.Fatalf("expected 8-character password to pass validation, got: %v", err)
	}
}

func TestSavePasswordRejectsNilReaderSlice(t *testing.T) {
	tmpHome := withTempHome(t)
	keyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x77}, 32), 0700); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	restoreReader := utils.SetReadPasswordStdin(func() ([]byte, error) {
		return nil, nil
	})
	defer restoreReader()

	exitCalled := false
	restoreExit := utils.SetExitFunc(func(code int) {
		if code != 0 {
			exitCalled = true
		}
	})
	savePassword(model.PwdFile{})
	restoreExit()

	if !exitCalled {
		t.Fatalf("expected ManageErrorAndExit to be called when reader returns (nil, nil)")
	}
	if _, statErr := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected password file not to be written when reader returns (nil, nil), stat err: %v", statErr)
	}
}

func TestSavePasswordInitialAndMismatch(t *testing.T) {
	tmpHome := withTempHome(t)
	keyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x77}, 32), 0700); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	stubPasswordSequence(t, "initial-master-password", "wrong-current-password")

	savePassword(model.PwdFile{})

	persisted, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to load persisted password file: %v", err)
	}
	if !strings.HasPrefix(persisted.MasterPassword, "pbkdf2-sha256$") {
		t.Fatalf("expected persisted master password to use pbkdf2-sha256$ prefix, got %q", persisted.MasterPassword)
	}
	if !utils.VerifyMasterPassword(persisted.MasterPassword, []byte("initial-master-password")) {
		t.Fatalf("expected persisted master password hash to verify against initial password")
	}

	savePassword(persisted)

	afterMismatch, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to read password file after mismatch attempt: %v", err)
	}
	if afterMismatch.MasterPassword != persisted.MasterPassword {
		t.Fatalf("expected master password hash to remain unchanged on verification mismatch, got %q, want %q", afterMismatch.MasterPassword, persisted.MasterPassword)
	}
}

func TestSavePasswordRotationAndPromptError(t *testing.T) {
	tmpHome := withTempHome(t)
	keyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x77}, 32), 0700); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	stubPasswordSequence(t, "initial-master-password", "initial-master-password", "rotated-master-password")

	savePassword(model.PwdFile{})
	persisted, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to load initial password file: %v", err)
	}

	savePassword(persisted)
	afterRotate, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to read password file after rotation: %v", err)
	}
	if afterRotate.MasterPassword == persisted.MasterPassword {
		t.Fatalf("expected rotated master password hash to differ from previous hash")
	}
	if !utils.VerifyMasterPassword(afterRotate.MasterPassword, []byte("rotated-master-password")) {
		t.Fatalf("expected rotated hash to verify against new master password")
	}
	if utils.VerifyMasterPassword(afterRotate.MasterPassword, []byte("initial-master-password")) {
		t.Fatalf("expected rotated hash to reject old master password")
	}

	exitCalled := false
	restoreExit := utils.SetExitFunc(func(code int) {
		if code != 0 {
			exitCalled = true
		}
	})
	defer restoreExit()

	savePassword(afterRotate)
	if !exitCalled {
		t.Fatalf("expected ManageErrorAndExit to be called when password prompt fails")
	}
	afterPromptErr, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to read password file after prompt failure: %v", err)
	}
	if afterPromptErr.MasterPassword != afterRotate.MasterPassword {
		t.Fatalf("expected master password hash to remain unchanged after prompt failure")
	}
}

func TestSavePasswordAbortsWhenEncryptionFails(t *testing.T) {
	tmpHome := withTempHome(t)
	stubPasswordSequence(t, "new-master-password")

	exitCalled := false
	restoreExit := utils.SetExitFunc(func(code int) {
		if code != 0 {
			exitCalled = true
		}
	})
	defer restoreExit()

	// No key file exists in tmpHome, so SaveFileErr must fail and trigger ManageErrorAndExit.
	savePassword(model.PwdFile{})
	if !exitCalled {
		t.Fatalf("expected ManageErrorAndExit to be invoked when encryption fails in savePassword")
	}
	if _, err := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected password file not to be written when encryption fails, got: %v", err)
	}
}

func TestManageErrorAndExitTerminatesOnError(t *testing.T) {
	exitCode := 0
	restore := utils.SetExitFunc(func(code int) {
		exitCode = code
	})
	defer restore()

	utils.ManageErrorAndExit(nil)
	if exitCode != 0 {
		t.Fatalf("expected no exit on nil error, got exit code %d", exitCode)
	}

	utils.ManageErrorAndExit(errors.New("fatal failure"))
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code on error, got %d", exitCode)
	}
}
