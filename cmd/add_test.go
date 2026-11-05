package cmd

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func TestReadPwdNameWithSpaces(t *testing.T) {
	name, err := readPwdName(strings.NewReader("my email account\n"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if name != "my email account" {
		t.Fatalf("expected %q, got %q", "my email account", name)
	}
}

func TestReadPwdNameTrimsSurroundingWhitespaceAndHandlesEOF(t *testing.T) {
	name, err := readPwdName(strings.NewReader("  work vpn account  "))
	if err != nil {
		t.Fatalf("expected no error on unterminated non-empty line, got %v", err)
	}
	if name != "work vpn account" {
		t.Fatalf("expected %q, got %q", "work vpn account", name)
	}
}

func TestReadPwdNameEmpty(t *testing.T) {
	_, err := readPwdName(strings.NewReader("   \n"))
	if err == nil {
		t.Fatal("expected error for empty password name, got nil")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("did not expect io.EOF for newline-terminated whitespace, got %v", err)
	}

	for _, tc := range []struct {
		name  string
		input string
	}{
		{name: "empty reader", input: ""},
		{name: "whitespace only before EOF", input: "   \t  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readPwdName(strings.NewReader(tc.input))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, io.EOF) {
				t.Fatalf("expected errors.Is(err, io.EOF) to be true, got %v", err)
			}
			if err == io.EOF || err.Error() == io.EOF.Error() {
				t.Fatalf("expected wrapped io.EOF with context, got bare %q", err)
			}
			if !strings.Contains(err.Error(), "read password name:") {
				t.Fatalf("expected operation context 'read password name:' in error, got %q", err.Error())
			}
		})
	}
}

func TestCanSavePasswordExistingKey(t *testing.T) {
	saved := map[string]string{"github": "secret"}

	proceed, err := canSavePassword(saved, "github", strings.NewReader("n\n"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if proceed {
		t.Fatal("expected proceed to be false when user declines overwrite")
	}

	proceed, err = canSavePassword(saved, "github", strings.NewReader("y\n"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !proceed {
		t.Fatal("expected proceed to be true when user confirms overwrite")
	}

	proceed, err = canSavePassword(saved, "github", strings.NewReader("  Y \n"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !proceed {
		t.Fatal("expected proceed to be true when user confirms overwrite with uppercase Y")
	}

	proceed, err = canSavePassword(saved, "github", strings.NewReader("\n"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if proceed {
		t.Fatal("expected proceed to be false on empty confirmation input")
	}

	proceed, err = canSavePassword(saved, "gitlab", strings.NewReader(""))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !proceed {
		t.Fatal("expected proceed to be true when key does not exist")
	}

	proceed, err = canSavePassword(nil, "github", strings.NewReader(""))
	if err != nil {
		t.Fatalf("expected no error with nil map, got %v", err)
	}
	if !proceed {
		t.Fatal("expected proceed to be true when map is nil")
	}
}

func TestSequentialPromptsWithSharedBufferedStdin(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantPwdName string
		wantProceed bool
	}{
		{
			name:        "confirms overwrite from buffered second line",
			input:       "github\ny\n",
			wantPwdName: "github",
			wantProceed: true,
		},
		{
			name:        "declines overwrite from buffered second line",
			input:       "github\nn\n",
			wantPwdName: "github",
			wantProceed: false,
		},
		{
			name:        "confirms overwrite on unterminated second line at EOF",
			input:       "  github  \n  Y  ",
			wantPwdName: "github",
			wantProceed: true,
		},
		{
			name:        "declines overwrite when EOF reached before second line",
			input:       "github\n",
			wantPwdName: "github",
			wantProceed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oldStdin := os.Stdin
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create stdin pipe: %v", err)
			}
			os.Stdin = r
			defer func() {
				os.Stdin = oldStdin
				_ = r.Close()
			}()

			if _, err := io.WriteString(w, tc.input); err != nil {
				t.Fatalf("failed to write to pipe: %v", err)
			}
			_ = w.Close()

			stdinReader := bufio.NewReader(os.Stdin)
			pwdName, err := readPwdName(stdinReader)
			if err != nil {
				t.Fatalf("expected no error reading password name, got %v", err)
			}
			if pwdName != tc.wantPwdName {
				t.Fatalf("expected password name %q, got %q", tc.wantPwdName, pwdName)
			}

			saved := map[string]string{"github": "secret"}
			proceed, err := canSavePassword(saved, pwdName, stdinReader)
			if err != nil {
				t.Fatalf("expected no error reading overwrite confirmation, got %v", err)
			}
			if proceed != tc.wantProceed {
				t.Fatalf("expected proceed=%v, got %v", tc.wantProceed, proceed)
			}
		})
	}
}

func TestSharedBufferedReaderSequentialPrompts(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantName    string
		wantProceed bool
	}{
		{
			name:        "confirms overwrite on second line",
			input:       "github\ny\n",
			wantName:    "github",
			wantProceed: true,
		},
		{
			name:        "confirms overwrite without trailing newline",
			input:       "github\ny",
			wantName:    "github",
			wantProceed: true,
		},
		{
			name:        "declines overwrite on second line",
			input:       "github\nn\n",
			wantName:    "github",
			wantProceed: false,
		},
		{
			name:        "eof on second prompt defaults to false",
			input:       "github\n",
			wantName:    "github",
			wantProceed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create stdin pipe: %v", err)
			}
			defer func() {
				_ = r.Close()
			}()

			if _, err := io.WriteString(w, tc.input); err != nil {
				_ = w.Close()
				t.Fatalf("failed to write piped input: %v", err)
			}
			_ = w.Close()

			oldStdin := os.Stdin
			os.Stdin = r
			defer func() {
				os.Stdin = oldStdin
			}()

			stdinReader := bufio.NewReader(os.Stdin)

			name, err := readPwdName(stdinReader)
			if err != nil {
				t.Fatalf("expected no error reading password name, got %v", err)
			}
			if name != tc.wantName {
				t.Fatalf("expected password name %q, got %q", tc.wantName, name)
			}

			saved := map[string]string{"github": "secret"}
			proceed, err := canSavePassword(saved, name, stdinReader)
			if err != nil {
				t.Fatalf("expected no error reading overwrite confirmation, got %v", err)
			}
			if proceed != tc.wantProceed {
				t.Fatalf("expected proceed=%v, got %v", tc.wantProceed, proceed)
			}
		})
	}
}

type failingReader struct {
	err error
}

func (f failingReader) Read(_ []byte) (int, error) {
	return 0, f.err
}

func TestPromptReadersPropagateReadErrors(t *testing.T) {
	readErr := errors.New("stdin read error")

	_, err := readPwdName(failingReader{err: readErr})
	if !errors.Is(err, readErr) {
		t.Fatalf("expected error %v from readPwdName, got %v", readErr, err)
	}
	if err == readErr || err.Error() == readErr.Error() {
		t.Fatalf("expected wrapped error with context from readPwdName, got bare %q", err)
	}
	if !strings.Contains(err.Error(), "read password name:") {
		t.Fatalf("expected operation context 'read password name:' in error, got %q", err.Error())
	}

	saved := map[string]string{"github": "secret"}
	proceed, err := canSavePassword(saved, "github", failingReader{err: readErr})
	if !errors.Is(err, readErr) {
		t.Fatalf("expected error %v from canSavePassword, got %v", readErr, err)
	}
	if proceed {
		t.Fatal("expected proceed to be false on read error")
	}
}

func TestSavePasswordRejectsEmptyCurrentPassword(t *testing.T) {
	// Isolate the vault from the real home directory and answer the prompt with
	// an empty current password so the test never reads from a real terminal.
	t.Setenv("HOME", t.TempDir())
	tmpHome := os.Getenv("HOME")
	prompts := 0
	promptHome := ""
	restorePrompt := utils.SetReadPasswordStdin(func() ([]byte, error) {
		prompts++
		promptHome = os.Getenv("HOME")
		return []byte{}, nil
	})
	t.Cleanup(restorePrompt)

	// captureStdout restores os.Stdout in a defer, so a failure or panic in
	// savePassword cannot leave it redirected.
	output := captureStdout(t, func() {
		savePassword(model.PwdFile{MasterPassword: "existing-master"})
	})

	if prompts != 1 {
		t.Fatalf("expected exactly one stubbed password prompt, got %d", prompts)
	}
	if promptHome != tmpHome {
		t.Fatalf("expected prompt to run with HOME=%q, got %q", tmpHome, promptHome)
	}
	if !strings.Contains(output, "Passwords do not match") {
		t.Fatalf("expected 'Passwords do not match' in output, got %q", output)
	}
	if strings.Contains(output, "Password saved") {
		t.Fatalf("did not expect 'Password saved' in output, got %q", output)
	}
	if _, err := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no vault file in isolated HOME, stat err: %v", err)
	}
}

func TestCaptureStdoutRestoresStdoutOnPanic(t *testing.T) {
	original := os.Stdout
	t.Cleanup(func() { os.Stdout = original })

	panicked := false
	func() {
		defer func() {
			panicked = recover() != nil
		}()
		captureStdout(t, func() {
			_, _ = io.WriteString(os.Stdout, "partial output")
			panic("savePassword failed")
		})
	}()

	if !panicked {
		t.Fatal("expected the panic to propagate out of captureStdout")
	}
	if os.Stdout != original {
		t.Fatal("expected os.Stdout to be restored after a panic during capture")
	}
}

func TestCaptureStdoutDrainsOutputLargerThanPipeBuffer(t *testing.T) {
	// 256 KiB exceeds common OS pipe buffers (~64 KiB); an undrained capture
	// would block the writer forever.
	payload := strings.Repeat("x", 256*1024)
	// On timeout t.Fatal returns while the capture goroutine may still hold
	// os.Stdout redirected to its pipe; restore it so later tests are unaffected.
	origStdout := os.Stdout
	t.Cleanup(func() { os.Stdout = origStdout })
	done := make(chan string, 1)
	go func() {
		done <- captureStdout(t, func() {
			_, _ = io.WriteString(os.Stdout, payload)
		})
	}()

	select {
	case got := <-done:
		if got != payload {
			t.Fatalf("expected %d captured bytes, got %d", len(payload), len(got))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("captureStdout blocked on output larger than the pipe buffer")
	}
}

func TestSavePasswordWhenMasterPasswordEmpty(t *testing.T) {
	// Restore the original working directory in case savePassword changes it.
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	stubPasswordSequence(t, "valid-master-password")

	output := captureStdout(t, func() {
		savePassword(model.PwdFile{MasterPassword: ""})
	})
	if strings.Contains(output, "Enter your current password:") {
		t.Fatalf("did not expect current password prompt when MasterPassword is empty, got %q", output)
	}
	if !strings.Contains(output, "Enter your new password:") {
		t.Fatalf("expected new password prompt when MasterPassword is empty, got %q", output)
	}
	if !strings.Contains(output, "Password saved") {
		t.Fatalf("expected 'Password saved' in output, got %q", output)
	}
}

func TestStorePasswordReportsSaveFailure(t *testing.T) {
	saveErr := errors.New("disk full")
	orig := saveVault
	t.Cleanup(func() { saveVault = orig })

	var gotIn error
	var savedValue string
	saveVault = func(p model.PwdFile, in error) error {
		gotIn, savedValue = in, p.SavedPasswords["github"]
		return saveErr
	}

	err := storePassword(model.PwdFile{}, "github", "secret")
	if !errors.Is(err, saveErr) {
		t.Fatalf("expected save error to be returned, got %v", err)
	}
	if !strings.Contains(err.Error(), `save password "github"`) {
		t.Fatalf("expected operation context in error, got %q", err.Error())
	}
	if gotIn != nil {
		t.Fatalf("expected no stale error passed to save, got %v", gotIn)
	}
	if savedValue != "secret" {
		t.Fatalf("expected password to be stored before save, got %q", savedValue)
	}

	saveVault = func(model.PwdFile, error) error { return nil }
	if err := storePassword(model.PwdFile{}, "github", "secret"); err != nil {
		t.Fatalf("expected nil on successful save, got %v", err)
	}
}

func TestStorePasswordRejectsEmptyValueWithoutOverwriting(t *testing.T) {
	orig := saveVault
	t.Cleanup(func() { saveVault = orig })

	saveCalled := false
	saveVault = func(model.PwdFile, error) error {
		saveCalled = true
		return nil
	}

	initial := model.PwdFile{
		MasterPassword: "hashed-master",
		SavedPasswords: map[string]string{
			"email":  "keep-me",
			"github": "old-secret",
		},
	}
	err := storePassword(initial, "github", "")
	if !errors.Is(err, errEmptyPassword) {
		t.Fatalf("expected errEmptyPassword, got %v", err)
	}
	if !strings.Contains(err.Error(), `save password "github"`) {
		t.Fatalf("expected operation context in error, got %q", err.Error())
	}
	if saveCalled {
		t.Fatal("expected vault not to be saved for an empty password")
	}
	if initial.SavedPasswords["github"] != "old-secret" {
		t.Fatalf("expected existing entry untouched, got %q", initial.SavedPasswords["github"])
	}
	if initial.SavedPasswords["email"] != "keep-me" {
		t.Fatalf("expected unrelated entry untouched, got %q", initial.SavedPasswords["email"])
	}
}

func TestStorePasswordPreservesExistingEntries(t *testing.T) {
	orig := saveVault
	t.Cleanup(func() { saveVault = orig })

	var saved model.PwdFile
	saveVault = func(p model.PwdFile, in error) error {
		if in != nil {
			t.Fatalf("expected nil input error, got %v", in)
		}
		saved = p
		return nil
	}

	initial := model.PwdFile{
		MasterPassword: "hashed-master",
		SavedPasswords: map[string]string{
			"email":  "keep-me",
			"github": "old-secret",
		},
	}
	if err := storePassword(initial, "github", "new-secret"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if saved.MasterPassword != "hashed-master" {
		t.Fatalf("expected master password preserved, got %q", saved.MasterPassword)
	}
	if saved.SavedPasswords["email"] != "keep-me" {
		t.Fatalf("expected unrelated entry preserved, got %q", saved.SavedPasswords["email"])
	}
	if saved.SavedPasswords["github"] != "new-secret" {
		t.Fatalf("expected overwritten value for github, got %q", saved.SavedPasswords["github"])
	}
}

func TestExecAddCmdRejectsEmptyPasswordAfterOverwriteConfirm(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", map[string]string{"github": "old-secret"})

	origCopy := addCopyFlag
	t.Cleanup(func() { addCopyFlag = origCopy })
	addCopyFlag = false

	stubPasswordSequence(t, "valid-master-pass", "")
	exitCount := captureExit(t)

	out := captureStdout(t, func() {
		feedStdinInput(t, "github\ny\n", func() {
			execAddCmd(addCmd, nil)
		})
	})

	if *exitCount == 0 {
		t.Fatal("expected ManageErrorAndExit to be called for an empty password")
	}
	if !strings.Contains(out, "password value cannot be empty") {
		t.Fatalf("expected empty password error in output, got %q", out)
	}
	utils.SetMasterKey([]byte("valid-master-pass"))
	loaded, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to reload vault: %v", err)
	}
	if loaded.SavedPasswords["github"] != "old-secret" {
		t.Fatalf("expected existing password kept, got %q", loaded.SavedPasswords["github"])
	}
}

func seedExecAddVault(t *testing.T, masterPass string, existing map[string]string) string {
	t.Helper()
	tmpHome := withTempHome(t)
	hashed, err := utils.HashMasterPassword([]byte(masterPass))
	if err != nil {
		t.Fatalf("failed to hash master password: %v", err)
	}
	utils.SetMasterKey([]byte(masterPass))
	pwdFile := model.PwdFile{
		MasterPassword: hashed,
		SavedPasswords: existing,
	}
	if err := utils.SaveFileErr(pwdFile, nil); err != nil {
		t.Fatalf("failed to seed vault: %v", err)
	}
	return tmpHome
}

func TestExecAddCmdSaveFailureAbortsBeforeClipboardAndExits(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", map[string]string{"existing": "keep"})

	origSave := saveVault
	origClip := clipboardWriteAll
	origCopy := addCopyFlag
	t.Cleanup(func() {
		saveVault = origSave
		clipboardWriteAll = origClip
		addCopyFlag = origCopy
	})

	saveErr := errors.New("write vault failed")
	saveVault = func(model.PwdFile, error) error {
		return saveErr
	}
	clipCalled := false
	clipboardWriteAll = func(string) error {
		clipCalled = true
		return nil
	}
	addCopyFlag = true

	stubPasswordSequence(t, "valid-master-pass", "new-secret-value")
	exitCount := captureExit(t)

	out := captureStdout(t, func() {
		feedStdinInput(t, "github\n", func() {
			execAddCmd(addCmd, nil)
		})
	})

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

func TestExecAddCmdPersistsAndCopiesOnSuccess(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", nil)

	origClip := clipboardWriteAll
	origCopy := addCopyFlag
	t.Cleanup(func() {
		clipboardWriteAll = origClip
		addCopyFlag = origCopy
	})

	var copied string
	clipboardWriteAll = func(text string) error {
		copied = text
		return nil
	}
	addCopyFlag = true

	stubPasswordSequence(t, "valid-master-pass", "super-secret-123")
	exitCount := captureExit(t)

	_ = captureStdout(t, func() {
		feedStdinInput(t, "github\n", func() {
			execAddCmd(addCmd, nil)
		})
	})

	if *exitCount != 0 {
		t.Fatalf("expected no error exit on successful add, got %d", *exitCount)
	}
	if copied != "super-secret-123" {
		t.Fatalf("expected password copied to clipboard after save, got %q", copied)
	}

	utils.SetMasterKey([]byte("valid-master-pass"))
	loaded, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to reload vault after add: %v", err)
	}
	if loaded.SavedPasswords["github"] != "super-secret-123" {
		t.Fatalf("expected saved password in vault, got %v", loaded.SavedPasswords)
	}
}

func TestExecAddCmdZeroesPromptedPasswordBuffer(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", nil)

	origClip := clipboardWriteAll
	origCopy := addCopyFlag
	t.Cleanup(func() {
		clipboardWriteAll = origClip
		addCopyFlag = origCopy
	})
	var copied string
	clipboardWriteAll = func(text string) error {
		copied = text
		return nil
	}
	addCopyFlag = true

	secretBuf := []byte("zero-me-secret")
	calls := 0
	restore := utils.SetReadPasswordStdin(func() ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("valid-master-pass"), nil
		}
		return secretBuf, nil
	})
	t.Cleanup(restore)
	exitCount := captureExit(t)

	_ = captureStdout(t, func() {
		feedStdinInput(t, "github\n", func() {
			execAddCmd(addCmd, nil)
		})
	})

	if *exitCount != 0 {
		t.Fatalf("expected no error exit, got %d", *exitCount)
	}
	for i, b := range secretBuf {
		if b != 0 {
			t.Fatalf("expected prompted password buffer zeroed, byte %d is %q (buffer %q)", i, b, secretBuf)
		}
	}
	if copied != "zero-me-secret" {
		t.Fatalf("expected password copied to clipboard, got %q", copied)
	}
	utils.SetMasterKey([]byte("valid-master-pass"))
	loaded, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to reload vault: %v", err)
	}
	if loaded.SavedPasswords["github"] != "zero-me-secret" {
		t.Fatalf("expected saved password in vault, got %v", loaded.SavedPasswords)
	}
}

func TestExecAddCmdSurfacesClipboardFailure(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", nil)

	origClip := clipboardWriteAll
	origCopy := addCopyFlag
	t.Cleanup(func() {
		clipboardWriteAll = origClip
		addCopyFlag = origCopy
	})
	clipboardWriteAll = func(string) error {
		return errors.New("no clipboard available")
	}
	addCopyFlag = true

	stubPasswordSequence(t, "valid-master-pass", "clip-fail-secret")
	exitCount := captureExit(t)

	out := captureStdout(t, func() {
		feedStdinInput(t, "github\n", func() {
			execAddCmd(addCmd, nil)
		})
	})

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
	utils.SetMasterKey([]byte("valid-master-pass"))
	loaded, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to reload vault: %v", err)
	}
	if loaded.SavedPasswords["github"] != "clip-fail-secret" {
		t.Fatalf("expected password still saved, got %v", loaded.SavedPasswords)
	}
}
