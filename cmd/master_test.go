package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
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

func writeTestKey(t *testing.T, tmpHome string, b byte) string {
	t.Helper()
	keyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{b}, 32), 0700); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	return keyPath
}

func TestGenerateKeyAbortsOnRandError(t *testing.T) {
	tmpHome := withTempHome(t)
	origRandRead := randRead
	defer func() { randRead = origRandRead }()

	rngErr := errors.New("rng failure")
	var capturedSaltBuf []byte
	randRead = func(r io.Reader, buf []byte) (int, error) {
		capturedSaltBuf = buf
		for i := range buf {
			buf[i] = 0x5a
		}
		return 0, rngErr
	}

	err := generateKey([]byte("valid-master-secret"))
	if !errors.Is(err, rngErr) || !strings.Contains(err.Error(), "read random key bytes:") {
		t.Fatalf("expected wrapped rng error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(tmpHome, utils.PwdFileKey)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected key file not to be written on rng error, stat err: %v", statErr)
	}
	if !bytes.Equal(capturedSaltBuf, make([]byte, len(capturedSaltBuf))) {
		t.Fatalf("expected salt buffer to be zeroed on rng error, got %x", capturedSaltBuf)
	}
}

func TestGenerateKeyReturnsErrorOnWriteFailure(t *testing.T) {
	tmpHome := withTempHome(t)
	origRandRead := randRead
	defer func() { randRead = origRandRead }()

	var capturedSaltBuf []byte
	randRead = func(r io.Reader, buf []byte) (int, error) {
		capturedSaltBuf = buf
		for i := range buf {
			buf[i] = 0xee
		}
		return len(buf), nil
	}
	if err := os.Mkdir(filepath.Join(tmpHome, utils.PwdFileKey), 0700); err != nil {
		t.Fatalf("failed to create directory at key path: %v", err)
	}

	err := generateKey([]byte("valid-master-secret"))
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || !strings.Contains(err.Error(), "write key file:") {
		t.Fatalf("expected wrapped *os.PathError from os.WriteFile, got %v", err)
	}
	if !bytes.Equal(capturedSaltBuf, make([]byte, len(capturedSaltBuf))) {
		t.Fatalf("expected salt buffer to be zeroed on write error, got %x", capturedSaltBuf)
	}
}

func TestGenerateKeyWritesExpectedKeyOnSuccess(t *testing.T) {
	tmpHome := withTempHome(t)
	origRandRead := randRead
	defer func() { randRead = origRandRead }()

	password := []byte("valid-master-secret")
	fixedSalt := bytes.Repeat([]byte{0xab}, 32)
	var capturedSaltBuf []byte
	randRead = func(r io.Reader, buf []byte) (int, error) {
		capturedSaltBuf = buf
		copy(buf, fixedSalt)
		return len(buf), nil
	}

	expectedKey, err := deriveKey(password, fixedSalt)
	if err != nil {
		t.Fatalf("deriveKey failed: %v", err)
	}
	if bytes.Equal(expectedKey, fixedSalt) || bytes.Equal(expectedKey, password) {
		t.Fatalf("expected derived key to differ from raw salt and password")
	}

	if err := generateKey(password); err != nil {
		t.Fatalf("expected nil error from generateKey, got: %v", err)
	}
	keyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat generated key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 || perm&0111 != 0 {
		t.Fatalf("expected key file permissions 0600 without execution bits, got %#o", perm)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(gotKey, expectedKey) {
		t.Fatalf("generated key mismatch: got %x, want %x (err=%v)", gotKey, expectedKey, err)
	}
	if bytes.Equal(gotKey, fixedSalt) {
		t.Fatalf("expected persisted key not to equal raw random salt bytes")
	}
	if !bytes.Equal(capturedSaltBuf, make([]byte, len(capturedSaltBuf))) {
		t.Fatalf("expected in-memory salt buffer to be zeroed after generateKey, got %x", capturedSaltBuf)
	}
}

func TestDeriveKeyAndGenerateKeyValidationBoundaries(t *testing.T) {
	tmpHome := withTempHome(t)
	saltA := bytes.Repeat([]byte{0x11}, 32)
	saltB := bytes.Repeat([]byte{0x22}, 32)

	for _, invalidPwd := range [][]byte{nil, []byte(""), []byte("   "), []byte("short77")} {
		if _, err := deriveKey(invalidPwd, saltA); err == nil {
			t.Fatalf("expected deriveKey to reject weak password %q", invalidPwd)
		}
		if err := generateKey(invalidPwd); err == nil {
			t.Fatalf("expected generateKey to reject weak password %q", invalidPwd)
		}
	}
	if _, statErr := os.Stat(filepath.Join(tmpHome, utils.PwdFileKey)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected no key file when generateKey rejects invalid password, got %v", statErr)
	}
	if _, err := deriveKey([]byte("valid-master-secret"), nil); err == nil || !strings.Contains(err.Error(), "salt cannot be empty") {
		t.Fatalf("expected empty salt error from deriveKey, got %v", err)
	}

	k1, err := deriveKey([]byte("password-alpha"), saltA)
	if err != nil || len(k1) != encryptionKeyLen {
		t.Fatalf("expected %d-byte derived key, got len=%d err=%v", encryptionKeyLen, len(k1), err)
	}
	k1Repeat, _ := deriveKey([]byte("password-alpha"), saltA)
	kDiffSalt, _ := deriveKey([]byte("password-alpha"), saltB)
	kDiffPwd, _ := deriveKey([]byte("password-bravo"), saltA)
	if !bytes.Equal(k1, k1Repeat) || bytes.Equal(k1, kDiffSalt) || bytes.Equal(k1, kDiffPwd) {
		t.Fatalf("expected deterministic key derivation sensitive to both password and salt")
	}
}

func TestExecMasterCmdDoesNotOverwriteKeyOnCorruptFile(t *testing.T) {
	tmpHome := withTempHome(t)
	existingKey := bytes.Repeat([]byte{0x42}, 32)
	keyPath := writeTestKey(t, tmpHome, 0x42)
	pwdPath := filepath.Join(tmpHome, utils.PwdFileName)
	corruptContent := bytes.Repeat([]byte{0x99}, 32)
	if err := os.WriteFile(pwdPath, corruptContent, 0700); err != nil {
		t.Fatalf("failed to write corrupt password file: %v", err)
	}

	execMasterCmd(masterCmd, nil)

	if gotKey, err := os.ReadFile(keyPath); err != nil || !bytes.Equal(gotKey, existingKey) {
		t.Fatalf("existing key was overwritten on non-ErrNotExist load failure (err=%v)", err)
	}
	if gotPwdFile, err := os.ReadFile(pwdPath); err != nil || !bytes.Equal(gotPwdFile, corruptContent) {
		t.Fatalf("existing password file was overwritten on non-ErrNotExist load failure (err=%v)", err)
	}
}

func TestExecMasterCmdAbortsWhenKeyGenerationFails(t *testing.T) {
	tmpHome := withTempHome(t)
	stubPasswordSequence(t, "first-time-secret")
	origRandRead := randRead
	defer func() { randRead = origRandRead }()

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
	tmpHome := withTempHome(t)
	stubPasswordSequence(t, "first-time-secret")
	execMasterCmd(masterCmd, nil)

	keyInfo, err := os.Stat(filepath.Join(tmpHome, utils.PwdFileKey))
	if err != nil {
		t.Fatalf("expected key file to exist after initial master command, got: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0600 || perm&0111 != 0 {
		t.Fatalf("expected initialized key file permissions 0600 without execution bits, got %#o", perm)
	}
	loaded, err := utils.GetPwdObj()
	if err != nil || !strings.HasPrefix(loaded.MasterPassword, "pbkdf2-sha256$") {
		t.Fatalf("expected salted PBKDF2 hash prefix, got %q (err=%v)", loaded.MasterPassword, err)
	}
	if !utils.VerifyMasterPassword(loaded.MasterPassword, []byte("first-time-secret")) {
		t.Fatalf("expected saved master password hash to verify against initial secret")
	}
}

func feedStdinInput(t *testing.T, input string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		_ = r.Close()
	}()
	if _, err := w.WriteString(input); err != nil {
		t.Fatalf("failed to write stdin input: %v", err)
	}
	_ = w.Close()
	fn()
}

func TestExecMasterCmdNormalizesUpdateConfirmation(t *testing.T) {
	_ = withTempHome(t)
	stubPasswordSequence(t,
		"initial-secret",
		"initial-secret", "updated-secret-1",
		"updated-secret-1", "updated-secret-2",
		"updated-secret-2", "updated-secret-3",
		"updated-secret-3", "updated-secret-4",
		"updated-secret-4", "updated-secret-5",
		"updated-secret-5", "updated-secret-6",
		"updated-secret-6", "updated-secret-7",
	)
	execMasterCmd(masterCmd, nil)

	affirmatives := []struct{ input, wantSecret string }{
		{"Y\n", "updated-secret-1"},
		{"yes\n", "updated-secret-2"},
		{"YES\n", "updated-secret-3"},
		{"  YeS\n", "updated-secret-4"},
		{"y\n", "updated-secret-5"},
		{"\tY\t\n", "updated-secret-6"},
		{"  yEs  \n", "updated-secret-7"},
	}
	for _, tc := range affirmatives {
		feedStdinInput(t, tc.input, func() { execMasterCmd(masterCmd, nil) })
		loaded, err := utils.GetPwdObj()
		if err != nil || !utils.VerifyMasterPassword(loaded.MasterPassword, []byte(tc.wantSecret)) {
			t.Fatalf("expected %q confirmation to update password to %q, err=%v", tc.input, tc.wantSecret, err)
		}
	}

	feedStdinInput(t, "n\n", func() { execMasterCmd(masterCmd, nil) })
	loaded, err := utils.GetPwdObj()
	if err != nil || !utils.VerifyMasterPassword(loaded.MasterPassword, []byte("updated-secret-7")) {
		t.Fatalf("expected 'n' confirmation to keep existing password, err=%v", err)
	}
}

func TestExecMasterCmdConfirmationBoundariesAndScanError(t *testing.T) {
	_ = withTempHome(t)
	stubPasswordSequence(t, "initial-secret")
	execMasterCmd(masterCmd, nil)

	initialLoaded, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("expected GetPwdObj to succeed after initial setup: %v", err)
	}
	for _, nonAffirmative := range []string{"N\n", "no\n", "NO\n", "yeah\n", "yess\n"} {
		feedStdinInput(t, nonAffirmative, func() { execMasterCmd(masterCmd, nil) })
		loaded, err := utils.GetPwdObj()
		if err != nil || loaded.MasterPassword != initialLoaded.MasterPassword {
			t.Fatalf("expected non-affirmative input %q not to modify master password (err=%v)", nonAffirmative, err)
		}
	}

	exitCalled := false
	restoreExit := utils.SetExitFunc(func(code int) {
		if code != 0 {
			exitCalled = true
		}
	})
	defer restoreExit()

	feedStdinInput(t, "", func() { execMasterCmd(masterCmd, nil) })
	if !exitCalled {
		t.Fatalf("expected ManageErrorAndExit to be called on EOF when scanning confirmation")
	}
	if afterScanErr, err := utils.GetPwdObj(); err != nil || afterScanErr.MasterPassword != initialLoaded.MasterPassword {
		t.Fatalf("expected master password to remain unchanged when confirmation scan fails (err=%v)", err)
	}
}

func TestGetPwdObjAfterCheckMasterPropagatesLoadError(t *testing.T) {
	_ = withTempHome(t)
	if _, err := utils.GetPwdObjAfterCheckMaster(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist when password file does not exist, got: %v", err)
	}
}

func TestGetPwdObjAfterCheckMasterRejectsMismatchedMasterPassword(t *testing.T) {
	if fi, err := os.Stdin.Stat(); err != nil || (fi.Mode()&os.ModeCharDevice) != 0 {
		t.Skip("skipping test when stdin is a terminal device")
	}
	tmpHome := withTempHome(t)
	writeTestKey(t, tmpHome, 0x11)

	hashed, err := utils.HashMasterPassword([]byte("non-empty-master-secret"))
	if err != nil {
		t.Fatalf("failed to hash master password: %v", err)
	}
	utils.SaveFile(model.PwdFile{MasterPassword: hashed}, nil)

	got, err := utils.GetPwdObjAfterCheckMaster()
	if err == nil || got.MasterPassword != "" {
		t.Fatalf("expected error and empty PwdFile on verification failure, got %+v, err=%v", got, err)
	}

	restoreReader := utils.SetReadPasswordStdin(func() ([]byte, error) {
		return []byte("non-empty-master-secret"), nil
	})
	defer restoreReader()

	gotValid, err := utils.GetPwdObjAfterCheckMaster()
	if err != nil || gotValid.MasterPassword != hashed {
		t.Fatalf("expected loaded MasterPassword %q, got %q (err=%v)", hashed, gotValid.MasterPassword, err)
	}
}

func TestHashAndVerifyMasterPassword(t *testing.T) {
	raw := "super-secret-master-password"
	hashed, err := utils.HashMasterPassword([]byte(raw))
	if err != nil || hashed == raw || strings.Contains(hashed, raw) {
		t.Fatalf("expected valid hashed password without raw secret, got %q (err=%v)", hashed, err)
	}
	if !utils.VerifyMasterPassword(hashed, []byte(raw)) || utils.VerifyMasterPassword(hashed, []byte("wrong-password")) {
		t.Fatalf("unexpected VerifyMasterPassword result")
	}
}

func TestVerifyMasterPasswordBoundariesAndLegacyFallback(t *testing.T) {
	raw := []byte("correct-horse-battery-staple")
	hash1, err1 := utils.HashMasterPassword(raw)
	hash2, err2 := utils.HashMasterPassword(raw)
	if err1 != nil || err2 != nil || hash1 == hash2 {
		t.Fatalf("expected distinct salted hashes, got %q, %q (errs: %v, %v)", hash1, hash2, err1, err2)
	}
	if !utils.VerifyMasterPassword(hash1, raw) || !utils.VerifyMasterPassword(hash2, raw) {
		t.Fatalf("expected both salted hashes to verify against original password")
	}

	invalidStored := []string{
		"", "pbkdf2-sha256$", "pbkdf2-sha256$onlysalt", "pbkdf2-sha256$a$b$c",
		"pbkdf2-sha256$not-hex$abcd", "pbkdf2-sha256$$abcd", "pbkdf2-sha256$abcd$not-hex",
		"pbkdf2-sha256$abcd$", "legacy-plaintext",
	}
	for _, stored := range invalidStored {
		if utils.VerifyMasterPassword(stored, raw) || utils.VerifyMasterPassword(stored, nil) {
			t.Fatalf("expected VerifyMasterPassword(%q) to return false", stored)
		}
	}
	if utils.VerifyMasterPassword("legacy-plaintext", []byte("legacy-plaintext")) {
		t.Fatalf("expected unprefixed plaintext verification to be rejected")
	}
}

func TestSaveFileReturnsErrorWhenKeyMissing(t *testing.T) {
	tmpHome := withTempHome(t)
	if err := utils.SaveFileErr(model.PwdFile{MasterPassword: "hash"}, nil); err == nil {
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
	writeTestKey(t, tmpHome, 0x33)
	pwdPath := filepath.Join(tmpHome, utils.PwdFileName)

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
	if err != nil || loaded.MasterPassword != expectedHash {
		t.Fatalf("loaded MasterPassword mismatch: got %q, want %q (err=%v)", loaded.MasterPassword, expectedHash, err)
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
	writeTestKey(t, tmpHome, 0x77)

	tests := []struct{ name, candidate, wantErr string }{
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
	writeTestKey(t, tmpHome, 0x77)

	if err := validateMasterPassword(nil); err == nil || !strings.Contains(err.Error(), "master password cannot be empty") {
		t.Fatalf("validateMasterPassword(nil) = %v, want empty master password error", err)
	}

	origRandRead := randRead
	defer func() { randRead = origRandRead }()
	keyGenCalled := false
	randRead = func(r io.Reader, buf []byte) (int, error) {
		keyGenCalled = true
		return len(buf), nil
	}

	restoreReader := utils.SetReadPasswordStdin(func() ([]byte, error) { return nil, nil })
	defer restoreReader()

	exitCount := 0
	restoreExit := utils.SetExitFunc(func(code int) {
		if code != 0 {
			exitCount++
		}
	})
	savePassword(model.PwdFile{})
	restoreExit()

	if exitCount != 1 {
		t.Fatalf("expected ManageErrorAndExit to be called once on validation failure when reader returns (nil, nil), got %d", exitCount)
	}
	if keyGenCalled {
		t.Fatalf("expected key generation not to run when new password slice is nil")
	}
	if _, statErr := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected password file not to be written when reader returns (nil, nil), stat err: %v", statErr)
	}
}

func TestSavePasswordInitialAndMismatch(t *testing.T) {
	tmpHome := withTempHome(t)
	writeTestKey(t, tmpHome, 0x77)
	stubPasswordSequence(t, "initial-master-password", "wrong-current-password")

	savePassword(model.PwdFile{})
	persisted, err := utils.GetPwdObj()
	if err != nil || !strings.HasPrefix(persisted.MasterPassword, "pbkdf2-sha256$") {
		t.Fatalf("expected persisted pbkdf2-sha256$ hash, got %q (err=%v)", persisted.MasterPassword, err)
	}
	if !utils.VerifyMasterPassword(persisted.MasterPassword, []byte("initial-master-password")) {
		t.Fatalf("expected persisted master password hash to verify against initial password")
	}

	savePassword(persisted)
	afterMismatch, err := utils.GetPwdObj()
	if err != nil || afterMismatch.MasterPassword != persisted.MasterPassword {
		t.Fatalf("expected master password hash to remain unchanged on mismatch (err=%v)", err)
	}
}

func TestSavePasswordRotationAndPromptError(t *testing.T) {
	tmpHome := withTempHome(t)
	writeTestKey(t, tmpHome, 0x77)
	stubPasswordSequence(t, "initial-master-password", "initial-master-password", "rotated-master-password")

	savePassword(model.PwdFile{})
	persisted, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to load initial password file: %v", err)
	}

	savePassword(persisted)
	afterRotate, err := utils.GetPwdObj()
	if err != nil || afterRotate.MasterPassword == persisted.MasterPassword {
		t.Fatalf("expected rotated master password hash to differ from previous hash (err=%v)", err)
	}
	if !utils.VerifyMasterPassword(afterRotate.MasterPassword, []byte("rotated-master-password")) ||
		utils.VerifyMasterPassword(afterRotate.MasterPassword, []byte("initial-master-password")) {
		t.Fatalf("expected rotated hash to verify new password and reject old password")
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
	if afterPromptErr, err := utils.GetPwdObj(); err != nil || afterPromptErr.MasterPassword != afterRotate.MasterPassword {
		t.Fatalf("expected master password hash to remain unchanged after prompt failure (err=%v)", err)
	}
}

func fillSyntheticSecret(dst []byte, seed byte) {
	for i := range dst {
		dst[i] = byte('!' + (int(seed)+i*13)%90)
	}
}

func verifyZeroedBuffersAndHeap(t *testing.T, tmpHome string, buffers [][]byte, wantCount int, seeds []byte) {
	t.Helper()
	dumpPath := filepath.Join(tmpHome, "heap.dump")
	dumpFile, err := os.Create(dumpPath)
	if err != nil {
		t.Fatalf("failed to create heap dump file: %v", err)
	}
	debug.WriteHeapDump(dumpFile.Fd())
	if err := dumpFile.Close(); err != nil {
		t.Fatalf("failed to close heap dump file: %v", err)
	}
	if len(buffers) != wantCount {
		t.Fatalf("expected %d password prompts, got %d", wantCount, len(buffers))
	}
	for i, buf := range buffers {
		if !bytes.Equal(buf, make([]byte, len(buf))) {
			t.Fatalf("expected password buffer %d to be zeroed in memory, got %x", i, buf)
		}
	}
	dumpBytes, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("failed to read heap dump: %v", err)
	}
	for _, seed := range seeds {
		probe := make([]byte, 24)
		fillSyntheticSecret(probe, seed)
		if bytes.Contains(dumpBytes, probe) {
			t.Fatalf("found raw secret for seed %d in runtime heap snapshot", seed)
		}
		clear(probe)
	}
}

func TestSavePasswordZeroesPasswordBuffersAndHeapSnapshot(t *testing.T) {
	tmpHome := withTempHome(t)
	writeTestKey(t, tmpHome, 0x77)

	var buffers [][]byte
	seeds := []byte{11, 29, 11, 47, 11, 83}
	lens := []int{24, 24, 24, 5, 24, 24}
	idx := 0
	restoreReader := utils.SetReadPasswordStdin(func() ([]byte, error) {
		if idx >= len(seeds) {
			return nil, errors.New("unexpected password prompt")
		}
		buf := make([]byte, lens[idx])
		fillSyntheticSecret(buf, seeds[idx])
		idx++
		buffers = append(buffers, buf)
		return buf, nil
	})
	defer restoreReader()

	savePassword(model.PwdFile{})
	persisted, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to load initial password file: %v", err)
	}
	savePassword(persisted)
	savePassword(persisted)
	savePassword(persisted)

	verifyZeroedBuffersAndHeap(t, tmpHome, buffers, len(seeds), []byte{11, 29, 83})
}

func TestSavePasswordAbortsWhenEncryptionFails(t *testing.T) {
	tmpHome := withTempHome(t)
	stubPasswordSequence(t, "new-master-password")
	pwdPath := filepath.Join(tmpHome, utils.PwdFileName)
	if err := os.Mkdir(pwdPath, 0700); err != nil {
		t.Fatalf("failed to create directory at password file path: %v", err)
	}

	exitCalled := false
	restoreExit := utils.SetExitFunc(func(code int) {
		if code != 0 {
			exitCalled = true
		}
	})
	defer restoreExit()

	savePassword(model.PwdFile{})
	if !exitCalled {
		t.Fatalf("expected ManageErrorAndExit to be invoked when saving encrypted file fails in savePassword")
	}
	if info, err := os.Stat(pwdPath); err != nil || !info.IsDir() {
		t.Fatalf("expected directory at password file path to remain untouched on save failure, got: %v", err)
	}
}

func TestManageErrorAndExitTerminatesOnError(t *testing.T) {
	exitCode := 0
	restore := utils.SetExitFunc(func(code int) { exitCode = code })
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
