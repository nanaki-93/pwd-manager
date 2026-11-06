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
	"unicode/utf8"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func TestReadPwdNameAcceptsValidNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "spaces inside name", input: "my email account\n", want: "my email account"},
		{name: "surrounding whitespace trimmed at EOF", input: "  work vpn account  ", want: "work vpn account"},
		{name: "printable Unicode", input: "conto bancario è già\n", want: "conto bancario è già"},
		{name: "max length two-byte runes", input: strings.Repeat("é", maxPwdNameLen) + "\n", want: strings.Repeat("é", maxPwdNameLen)},
		{name: "max length ASCII at EOF", input: strings.Repeat("a", maxPwdNameLen), want: strings.Repeat("a", maxPwdNameLen)},
		{name: "max length four-byte runes at EOF", input: strings.Repeat("😀", maxPwdNameLen), want: strings.Repeat("😀", maxPwdNameLen)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPwdName(strings.NewReader(tc.input))
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q, nil", got, err, tc.want)
			}
		})
	}
}

func TestReadPwdNameAcceptsLongestNameAndKeepsRest(t *testing.T) {
	longest := strings.Repeat("😀", maxPwdNameLen)
	reader := bufio.NewReader(strings.NewReader(longest + "\r\ny\n"))

	name, err := readPwdName(reader)
	if err != nil {
		t.Fatalf("expected longest valid name to be accepted, got %v", err)
	}
	if name != longest {
		t.Fatalf("expected name of %d runes, got %q", maxPwdNameLen, name)
	}
	rest, err := reader.ReadString('\n')
	if err != nil || rest != "y\n" {
		t.Fatalf("expected remaining input %q, got %q (err %v)", "y\n", rest, err)
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

func TestReadPwdNameRejectsInvalidNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{name: "ANSI escape sequence", input: "evil\x1b[2J\x1b]0;pwned\x07name\n"},
		{name: "bare escape byte", input: "a\x1bb\n"},
		{name: "embedded NUL", input: "a\x00b\n"},
		{name: "carriage return", input: "fake\rname\n"},
		{name: "embedded tab", input: "a\tb\n"},
		{name: "C1 control CSI", input: "a\u009bb\n"},
		{name: "bidi override", input: "a‮b\n"},
		{name: "invalid UTF-8", input: "a\xffb\n"},
		{name: "too long", input: strings.Repeat("x", maxPwdNameLen+1) + "\n"},
		{name: "too long Unicode at EOF", input: strings.Repeat("é", maxPwdNameLen+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, err := readPwdName(strings.NewReader(tc.input))
			if err == nil {
				t.Fatalf("expected rejection, got name %q", name)
			}
			if !errors.Is(err, errInvalidPwdName) {
				t.Fatalf("expected errInvalidPwdName, got %q", err.Error())
			}
			if name != "" {
				t.Fatalf("expected empty name on rejection, got %q", name)
			}
			if strings.ContainsAny(err.Error(), "\x1b\x00\r\a") {
				t.Fatalf("error message must not echo raw control bytes: %q", err.Error())
			}
		})
	}
}

// countingReader counts the bytes its caller pulls from the wrapped reader.
type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func TestReadPwdNameBoundsInput(t *testing.T) {
	for _, tc := range []struct {
		name       string
		terminator string
	}{
		{name: "newline-terminated", terminator: "\n"},
		{name: "unterminated", terminator: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &countingReader{r: strings.NewReader(strings.Repeat("a", 1<<20) + tc.terminator)}
			name, err := readPwdName(src)
			if !errors.Is(err, errInvalidPwdName) || name != "" {
				t.Fatalf("oversized name: got %q, %v; want empty name and errInvalidPwdName", name, err)
			}
			// One bufio fill past the bound is allowed; the whole line is not.
			if limit := maxPwdNameLen*utf8.UTFMax + len("\r\n") + 4096; src.read > limit {
				t.Fatalf("readPwdName consumed %d bytes, want at most %d", src.read, limit)
			}
		})
	}
}

func TestCanSavePassword(t *testing.T) {
	saved := map[string]string{"github": "secret"}
	for _, tc := range []struct {
		name  string
		saved map[string]string
		key   string
		input string
		want  bool
	}{
		{name: "declines overwrite", saved: saved, key: "github", input: "n\n", want: false},
		{name: "confirms overwrite", saved: saved, key: "github", input: "y\n", want: true},
		{name: "confirms with padded uppercase Y", saved: saved, key: "github", input: "  Y \n", want: true},
		{name: "empty confirmation declines", saved: saved, key: "github", input: "\n", want: false},
		{name: "new key needs no confirmation", saved: saved, key: "gitlab", input: "", want: true},
		{name: "nil map needs no confirmation", saved: nil, key: "github", input: "", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proceed, err := canSavePassword(tc.saved, tc.key, strings.NewReader(tc.input))
			if err != nil || proceed != tc.want {
				t.Fatalf("got proceed=%v, err=%v; want %v, nil", proceed, err, tc.want)
			}
		})
	}
}

func TestSequentialPromptsWithSharedBufferedStdin(t *testing.T) {
	for _, tc := range []struct {
		name        string
		input       string
		wantProceed bool
	}{
		{name: "confirms overwrite from buffered second line", input: "github\ny\n", wantProceed: true},
		{name: "declines overwrite from buffered second line", input: "github\nn\n", wantProceed: false},
		{name: "confirms overwrite on unterminated second line at EOF", input: "  github  \n  Y  ", wantProceed: true},
		{name: "declines overwrite when EOF reached before second line", input: "github\n", wantProceed: false},
	} {
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
				_ = w.Close()
				t.Fatalf("failed to write to pipe: %v", err)
			}
			_ = w.Close()

			stdinReader := bufio.NewReader(os.Stdin)
			pwdName, err := readPwdName(stdinReader)
			if err != nil || pwdName != "github" {
				t.Fatalf("expected password name %q, got %q (err %v)", "github", pwdName, err)
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
	restorePrompt := setUtilsReadPassword(func() ([]byte, error) {
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

func TestStorePasswordPersistsNonemptyValues(t *testing.T) {
	orig := saveVault
	t.Cleanup(func() { saveVault = orig })

	for _, value := range []string{" ", "\t\n", "x", "\x00", "🔐"} {
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
			if err := storePassword(model.PwdFile{}, "new-entry", value); err != nil {
				t.Fatalf("nonempty value rejected: %v", err)
			}
			if calls != 1 || saved.SavedPasswords["new-entry"] != value {
				t.Fatalf("expected one save preserving the exact nonempty value; calls=%d", calls)
			}
		})
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
	if got := initial.SavedPasswords["github"]; got != "new-secret" {
		t.Fatalf("expected caller's map to keep the new value after a successful save, got %q", got)
	}
}

func TestStorePasswordRollsBackMapOnSaveFailure(t *testing.T) {
	orig := saveVault
	t.Cleanup(func() { saveVault = orig })
	saveErr := errors.New("disk full")

	for _, tc := range []struct {
		name    string
		initial map[string]string
	}{
		{name: "overwrite restores previous value", initial: map[string]string{"email": "keep-me", "github": "old-secret"}},
		{name: "new key is removed", initial: map[string]string{"email": "keep-me"}},
		{name: "preexisting empty value stays present", initial: map[string]string{"github": ""}},
		{name: "nil map stays empty", initial: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var savedGithub string
			var gotIn error
			saveVault = func(p model.PwdFile, in error) error {
				savedGithub, gotIn = p.SavedPasswords["github"], in
				return saveErr
			}
			want := make(map[string]string, len(tc.initial))
			for k, v := range tc.initial {
				want[k] = v
			}
			pwdObj := model.PwdFile{MasterPassword: "hashed-master", SavedPasswords: tc.initial}

			err := storePassword(pwdObj, "github", "new-secret")
			if !errors.Is(err, saveErr) || !strings.Contains(err.Error(), `save password "github"`) {
				t.Fatalf("expected save error wrapped with context, got %v", err)
			}
			if savedGithub != "new-secret" || gotIn != nil {
				t.Fatalf("expected new value and no stale error passed to save, got %q, %v", savedGithub, gotIn)
			}
			if len(pwdObj.SavedPasswords) != len(want) {
				t.Fatalf("expected map %v, got %v", want, pwdObj.SavedPasswords)
			}
			for k, v := range want {
				if got, ok := pwdObj.SavedPasswords[k]; !ok || got != v {
					t.Fatalf("expected %q=%q, got %q (present=%v)", k, v, got, ok)
				}
			}
		})
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

func TestExecAddCmdRejectsEmptyPasswordAfterOverwriteConfirm(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", map[string]string{"github": "old-secret"})
	stubAddClipboard(t, false, clipboardWriteAll)
	stubPasswordSequence(t, "valid-master-pass", "")
	exitCount := captureExit(t)

	out := runExecAdd(t, "github\ny\n")

	if *exitCount == 0 {
		t.Fatal("expected ManageErrorAndExit to be called for an empty password")
	}
	if !strings.Contains(out, "password value cannot be empty") {
		t.Fatalf("expected empty password error in output, got %q", out)
	}
	if saved := loadSavedPasswords(t, "valid-master-pass"); saved["github"] != "old-secret" {
		t.Fatalf("expected existing password kept, got %q", saved["github"])
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
