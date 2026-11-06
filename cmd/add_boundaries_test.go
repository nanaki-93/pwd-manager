package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func TestStorePasswordValueBoundaries(t *testing.T) {
	orig := saveVault
	t.Cleanup(func() { saveVault = orig })

	for _, value := range []string{"", " ", "\t\n", "x", "\x00", "🔐"} {
		t.Run("value="+value, func(t *testing.T) {
			calls := 0
			var saved model.PwdFile
			saveVault = func(p model.PwdFile, in error) error {
				if in != nil {
					t.Fatalf("unexpected incoming error: %v", in)
				}
				calls++
				saved = p
				return nil
			}
			err := storePassword(model.PwdFile{}, "new-entry", value)
			if value == "" {
				if !errors.Is(err, errEmptyPassword) || calls != 0 {
					t.Fatalf("empty value: error=%v, save calls=%d; want rejection without persistence", err, calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("nonempty value rejected: %v", err)
			}
			if calls != 1 || saved.SavedPasswords["new-entry"] != value {
				t.Fatalf("expected one save preserving the exact nonempty value; calls=%d", calls)
			}
		})
	}
}

func TestExecAddCmdWithoutCopyDoesNotAccessClipboard(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", map[string]string{"existing": "keep"})
	origClip, origCopy := clipboardWriteAll, addCopyFlag
	t.Cleanup(func() {
		clipboardWriteAll = origClip
		addCopyFlag = origCopy
	})
	calls := 0
	clipboardWriteAll = func(string) error {
		calls++
		return errors.New("clipboard must not be accessed")
	}
	addCopyFlag = false
	stubPasswordSequence(t, "valid-master-pass", "no-copy-secret")
	exits := captureExit(t)
	captureStdout(t, func() {
		feedStdinInput(t, "github\n", func() {
			execAddCmd(addCmd, nil)
		})
	})
	if calls != 0 || *exits != 0 {
		t.Fatalf("without --copy: clipboard calls=%d, exits=%d; want neither", calls, *exits)
	}
	utils.SetMasterKey([]byte("valid-master-pass"))
	loaded, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("reload saved vault: %v", err)
	}
	if loaded.SavedPasswords["github"] != "no-copy-secret" || loaded.SavedPasswords["existing"] != "keep" {
		t.Fatal("add without --copy must persist the new value and preserve existing entries")
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
	if err := utils.SaveFileErr(model.PwdFile{MasterPassword: hashed}, nil); err != nil {
		t.Fatalf("SaveFileErr: %v", err)
	}

	got, err := utils.GetPwdObjAfterCheckMaster()
	if err == nil || got.MasterPassword != "" {
		t.Fatalf("expected error and empty PwdFile on verification failure, got %+v, err=%v", got, err)
	}

	restoreReader := setUtilsReadPassword(func() ([]byte, error) {
		return []byte("non-empty-master-secret"), nil
	})
	defer restoreReader()

	gotValid, err := utils.GetPwdObjAfterCheckMaster()
	if err != nil || gotValid.MasterPassword != hashed {
		t.Fatalf("expected loaded MasterPassword %q, got %q (err=%v)", hashed, gotValid.MasterPassword, err)
	}
}

func TestHashAndVerifyMasterPassword(t *testing.T) {
	raw := []byte("correct-horse-battery-staple")
	hash1, err1 := utils.HashMasterPassword(raw)
	hash2, err2 := utils.HashMasterPassword(raw)
	if err1 != nil || err2 != nil || hash1 == hash2 || strings.Contains(hash1, string(raw)) {
		t.Fatalf("expected distinct salted hashes without raw secret, got %q, %q (errs: %v, %v)", hash1, hash2, err1, err2)
	}
	if !utils.VerifyMasterPassword(hash1, raw) || !utils.VerifyMasterPassword(hash2, raw) {
		t.Fatalf("expected both salted hashes to verify against original password")
	}
	if utils.VerifyMasterPassword(hash1, []byte("wrong-password")) {
		t.Fatalf("expected wrong password to be rejected")
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

func TestSaveFileRejectsMissingKeyUpstreamAndCipherErrors(t *testing.T) {
	tmpHome := withTempHome(t)
	if err := utils.SaveFileErr(model.PwdFile{MasterPassword: "hash"}, nil); err == nil {
		t.Fatalf("expected SaveFileErr to return error when key file is missing")
	}
	if _, statErr := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected encrypted file not to be created when encryption fails, stat err: %v", statErr)
	}

	inErr := errors.New("upstream failure")
	if err := utils.SaveFileErr(model.PwdFile{MasterPassword: "hash"}, inErr); !errors.Is(err, inErr) {
		t.Fatalf("expected SaveFileErr to return input error %v, got %v", inErr, err)
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
	if err := utils.SaveFileErr(model.PwdFile{MasterPassword: expectedHash}, nil); err != nil {
		t.Fatalf("SaveFileErr: %v", err)
	}
	loaded, err := utils.GetPwdObj()
	if err != nil || loaded.MasterPassword != expectedHash {
		t.Fatalf("loaded MasterPassword mismatch: got %q, want %q (err=%v)", loaded.MasterPassword, expectedHash, err)
	}
}

func TestManageErrorAndExitTerminatesOnError(t *testing.T) {
	exitCode := 0
	restore := setUtilsExit(func(code int) { exitCode = code })
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
