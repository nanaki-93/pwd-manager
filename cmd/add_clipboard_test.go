package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

// fakeClipboard swaps the clipboard hooks for an in-memory clipboard.
func fakeClipboard(t *testing.T, readErr, writeErr error) *string {
	t.Helper()
	origRead, origWrite := clipboardReadAll, clipboardWriteAll
	t.Cleanup(func() { clipboardReadAll, clipboardWriteAll = origRead, origWrite })
	content := new(string)
	clipboardReadAll = func() (string, error) { return *content, readErr }
	clipboardWriteAll = func(s string) error {
		if writeErr != nil && s == "" {
			return writeErr
		}
		*content = s
		return nil
	}
	return content
}

func assertWiped(t *testing.T, b []byte) {
	t.Helper()
	for i, c := range b {
		if c != 0 {
			t.Fatalf("prompted password bytes not wiped at index %d: %q", i, b)
		}
	}
}

func TestAddPromptedPasswordWipesBytesOnEveryPath(t *testing.T) {
	origSave, origWrite, origRead, origClearer := saveVault, clipboardWriteAll, clipboardReadAll, clipboardClearer
	t.Cleanup(func() {
		saveVault, clipboardWriteAll = origSave, origWrite
		clipboardReadAll, clipboardClearer = origRead, origClearer
	})
	clipboardReadAll = func() (string, error) { return "", nil }
	clipboardClearer = func(string) error { return nil }

	saveErr := errors.New("disk full")
	clipErr := errors.New("no clipboard")
	for _, tc := range []struct {
		name    string
		saveErr error
		clipErr error
		copy    bool
		wantErr error
	}{
		{name: "success with copy", copy: true},
		{name: "save failure", saveErr: saveErr, wantErr: saveErr},
		{name: "clipboard failure", copy: true, clipErr: clipErr, wantErr: clipErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var saved, copied string
			saveVault = func(p model.PwdFile, _ error) error {
				saved = p.SavedPasswords["github"]
				return tc.saveErr
			}
			clipboardWriteAll = func(s string) error {
				copied = s
				return tc.clipErr
			}
			pwdBytes := []byte("s3cret")
			pwdObj := model.PwdFile{SavedPasswords: map[string]string{}}

			err := addPromptedPassword(pwdObj, "github", pwdBytes, tc.copy)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
			assertWiped(t, pwdBytes)
			if saved != "s3cret" {
				t.Fatalf("expected value passed to save, got %q", saved)
			}
			if tc.copy && tc.saveErr == nil && copied != "s3cret" {
				t.Fatalf("expected value copied to clipboard, got %q", copied)
			}
		})
	}
}

func TestAddPromptedPasswordRejectsEmptyBeforeSaving(t *testing.T) {
	origSave := saveVault
	t.Cleanup(func() { saveVault = origSave })
	saveVault = func(model.PwdFile, error) error {
		t.Fatal("save must not be called for an empty password")
		return nil
	}

	pwdObj := model.PwdFile{SavedPasswords: map[string]string{"github": "keep"}}
	err := addPromptedPassword(pwdObj, "github", []byte{}, true)
	if !errors.Is(err, errEmptyPassword) {
		t.Fatalf("expected errEmptyPassword, got %v", err)
	}
	if pwdObj.SavedPasswords["github"] != "keep" {
		t.Fatalf("existing entry must be untouched, got %q", pwdObj.SavedPasswords["github"])
	}
}

func TestAddPromptedPasswordClearsCopiedPassword(t *testing.T) {
	origSave, origClearer := saveVault, clipboardClearer
	t.Cleanup(func() { saveVault, clipboardClearer = origSave, origClearer })
	saveVault = func(model.PwdFile, error) error { return nil }
	content := fakeClipboard(t, nil, nil)
	clipboardClearer = func(pwd string) error {
		if *content != pwd {
			t.Fatalf("clearer must run after copy, clipboard=%q", *content)
		}
		return verifyAndClearClipboard(pwd)
	}

	pwdObj := model.PwdFile{SavedPasswords: map[string]string{}}
	if err := addPromptedPassword(pwdObj, "github", []byte("s3cret"), true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *content != "" {
		t.Fatalf("expected clipboard cleared after add --copy, still holds %q", *content)
	}
}

func TestAddPromptedPasswordClearFailureKeepsSaveAndWipes(t *testing.T) {
	origSave, origClearer := saveVault, clipboardClearer
	t.Cleanup(func() { saveVault, clipboardClearer = origSave, origClearer })
	saveVault = func(model.PwdFile, error) error { return nil }
	content := fakeClipboard(t, nil, nil)
	clearErr := errors.New("clear failed")
	clipboardClearer = func(string) error { return clearErr }

	secret := []byte("s3cret")
	vault := model.PwdFile{SavedPasswords: map[string]string{}}
	err := addPromptedPassword(vault, "github", secret, true)
	if !errors.Is(err, clearErr) || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("expected wrapped clear error without secret, got %v", err)
	}
	assertWiped(t, secret)
	if vault.SavedPasswords["github"] != "s3cret" || *content != "s3cret" {
		t.Fatal("clear failure must not roll back a successful save or corrupt the copied value")
	}
}

func TestVerifyAndClearClipboard(t *testing.T) {
	readErr := errors.New("read failed")
	writeErr := errors.New("write failed")
	for _, tc := range []struct {
		name     string
		initial  string
		readErr  error
		writeErr error
		want     string
		wantErrs []error
	}{
		{name: "clears when still holding secret", initial: "s3cret", want: ""},
		{name: "keeps value the user copied since", initial: "other", want: "other"},
		{name: "unreadable clipboard cleared anyway", initial: "s3cret", readErr: readErr, want: "", wantErrs: []error{readErr}},
		{name: "clear failure reported", initial: "s3cret", writeErr: writeErr, want: "s3cret", wantErrs: []error{writeErr}},
		{name: "both failures reported", initial: "s3cret", readErr: readErr, writeErr: writeErr, want: "s3cret", wantErrs: []error{readErr, writeErr}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := fakeClipboard(t, tc.readErr, tc.writeErr)
			*content = tc.initial
			err := verifyAndClearClipboard("s3cret")
			if len(tc.wantErrs) == 0 && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			for _, want := range tc.wantErrs {
				if !errors.Is(err, want) {
					t.Fatalf("expected error wrapping %v, got %v", want, err)
				}
			}
			if *content != tc.want {
				t.Fatalf("expected clipboard %q, got %q", tc.want, *content)
			}
		})
	}
}

// stubAddClipboard sets the --copy flag, replaces the clipboard writer and
// stubs the clipboard reader and clearer with no-ops for one test, restoring
// all of them afterwards.
func stubAddClipboard(t *testing.T, copyFlag bool, write func(string) error) {
	t.Helper()
	origWrite, origRead, origClearer, origCopy := clipboardWriteAll, clipboardReadAll, clipboardClearer, addCopyFlag
	t.Cleanup(func() {
		clipboardWriteAll = origWrite
		clipboardReadAll = origRead
		clipboardClearer = origClearer
		addCopyFlag = origCopy
	})
	clipboardWriteAll = write
	clipboardReadAll = func() (string, error) { return "", nil }
	clipboardClearer = func(string) error { return nil }
	addCopyFlag = copyFlag
}

func TestStubAddClipboardIsolatesAndRestoresHooks(t *testing.T) {
	origWrite, origRead, origClearer, origCopy := clipboardWriteAll, clipboardReadAll, clipboardClearer, addCopyFlag
	t.Cleanup(func() {
		clipboardWriteAll, clipboardReadAll, clipboardClearer, addCopyFlag = origWrite, origRead, origClearer, origCopy
	})
	writeErr, readErr, clearErr := errors.New("original write"), errors.New("original read"), errors.New("original clear")
	clipboardWriteAll = func(string) error { return writeErr }
	clipboardReadAll = func() (string, error) { return "original", readErr }
	clipboardClearer = func(string) error { return clearErr }
	addCopyFlag = false

	t.Run("stubbed", func(t *testing.T) {
		stubAddClipboard(t, true, func(string) error { return nil })
		if !addCopyFlag || clipboardWriteAll("secret") != nil {
			t.Error("expected copy flag and replacement writer")
		}
		if got, err := clipboardReadAll(); got != "" || err != nil {
			t.Errorf("stubbed read = %q, %v; want empty and nil", got, err)
		}
		if err := clipboardClearer("secret"); err != nil {
			t.Errorf("stubbed clearer: %v", err)
		}
	})
	if addCopyFlag || !errors.Is(clipboardWriteAll(""), writeErr) {
		t.Error("writer or copy flag not restored")
	}
	if got, err := clipboardReadAll(); got != "original" || !errors.Is(err, readErr) {
		t.Errorf("restored read = %q, %v", got, err)
	}
	if err := clipboardClearer("secret"); !errors.Is(err, clearErr) {
		t.Errorf("restored clearer = %v", err)
	}
}

// runExecAdd runs the add command with stdin input and returns its stdout.
func runExecAdd(t *testing.T, input string) string {
	t.Helper()
	return captureStdout(t, func() {
		feedStdinInput(t, input, func() {
			execAddCmd(addCmd, nil)
		})
	})
}

// loadSavedPasswords reopens the seeded vault and returns its entries.
func loadSavedPasswords(t *testing.T, masterPass string) map[string]string {
	t.Helper()
	utils.SetMasterKey([]byte(masterPass))
	loaded, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to reload vault: %v", err)
	}
	return loaded.SavedPasswords
}

func TestExecAddCmdSaveFailureAbortsBeforeClipboardAndExits(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", map[string]string{"existing": "keep"})

	origSave := saveVault
	t.Cleanup(func() { saveVault = origSave })
	saveVault = func(model.PwdFile, error) error {
		return errors.New("write vault failed")
	}
	clipCalled := false
	stubAddClipboard(t, true, func(string) error {
		clipCalled = true
		return nil
	})

	stubPasswordSequence(t, "valid-master-pass", "new-secret-value")
	exitCount := captureExit(t)
	out := runExecAdd(t, "github\n")

	if *exitCount == 0 {
		t.Fatal("expected ManageErrorAndExit to be called on save failure")
	}
	if clipCalled {
		t.Fatal("expected clipboard not to be written when vault save fails")
	}
	if !strings.Contains(out, `save password "github": write vault failed`) {
		t.Fatalf("expected wrapped save failure in output, got %q", out)
	}
	if strings.Contains(out, "new-secret-value") {
		t.Fatalf("expected secret password not to leak to stdout, got %q", out)
	}
}

func TestExecAddCmdPersistsCopiesAndZeroesPromptedPassword(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", nil)

	var copied string
	stubAddClipboard(t, true, func(text string) error {
		copied = text
		return nil
	})

	secretBuf := []byte("zero-me-secret")
	calls := 0
	restore := setUtilsReadPassword(func() ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("valid-master-pass"), nil
		}
		return secretBuf, nil
	})
	t.Cleanup(restore)
	exitCount := captureExit(t)

	_ = runExecAdd(t, "github\n")

	if *exitCount != 0 {
		t.Fatalf("expected no error exit on successful add, got %d", *exitCount)
	}
	assertWiped(t, secretBuf)
	if copied != "zero-me-secret" {
		t.Fatalf("expected password copied to clipboard after save, got %q", copied)
	}
	if saved := loadSavedPasswords(t, "valid-master-pass"); saved["github"] != "zero-me-secret" {
		t.Fatalf("expected saved password in vault, got %v", saved)
	}
}

func TestExecAddCmdSurfacesClipboardFailure(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", nil)
	stubAddClipboard(t, true, func(string) error {
		return errors.New("no clipboard available")
	})

	stubPasswordSequence(t, "valid-master-pass", "clip-fail-secret")
	exitCount := captureExit(t)
	out := runExecAdd(t, "github\n")

	if *exitCount == 0 {
		t.Fatal("expected ManageErrorAndExit to be called on clipboard failure")
	}
	want := `password "github" saved, but failed to copy password to clipboard: no clipboard available`
	if !strings.Contains(out, want) {
		t.Fatalf("expected %q in output, got %q", want, out)
	}
	if strings.Contains(out, "clip-fail-secret") {
		t.Fatalf("expected secret not to leak to stdout, got %q", out)
	}
	if saved := loadSavedPasswords(t, "valid-master-pass"); saved["github"] != "clip-fail-secret" {
		t.Fatalf("expected password still saved, got %v", saved)
	}
}

func TestExecAddCmdWithoutCopyDoesNotAccessClipboard(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", map[string]string{"existing": "keep"})
	calls := 0
	stubAddClipboard(t, false, func(string) error {
		calls++
		return errors.New("clipboard must not be accessed")
	})
	stubPasswordSequence(t, "valid-master-pass", "no-copy-secret")
	exits := captureExit(t)
	runExecAdd(t, "github\n")

	if calls != 0 || *exits != 0 {
		t.Fatalf("without --copy: clipboard calls=%d, exits=%d; want neither", calls, *exits)
	}
	saved := loadSavedPasswords(t, "valid-master-pass")
	if saved["github"] != "no-copy-secret" || saved["existing"] != "keep" {
		t.Fatal("add without --copy must persist the new value and preserve existing entries")
	}
}
