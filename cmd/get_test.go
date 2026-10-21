package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	fn()

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String()
}

func TestGetAndAddFlagsRegistered(t *testing.T) {
	getFlag := getCmd.Flags().Lookup("copy")
	if getFlag == nil || getFlag.Shorthand != "c" {
		t.Fatalf("expected --copy / -c flag on getCmd, got %+v", getFlag)
	}
	if getFlag.DefValue != "false" {
		t.Fatalf("expected default value 'false' for get --copy, got %q", getFlag.DefValue)
	}

	addFlag := addCmd.Flags().Lookup("copy")
	if addFlag == nil || addFlag.Shorthand != "c" {
		t.Fatalf("expected --copy / -c flag on addCmd, got %+v", addFlag)
	}
	if addFlag.DefValue != "false" {
		t.Fatalf("expected default value 'false' for add --copy, got %q", addFlag.DefValue)
	}
}

func TestGetAndAddCopyFlagParsing(t *testing.T) {
	defer func() {
		getCopyFlag = false
		addCopyFlag = false
		nameFlag = ""
	}()

	if err := getCmd.Flags().Parse([]string{"-n", "github", "-c"}); err != nil {
		t.Fatalf("unexpected parse error on getCmd -c: %v", err)
	}
	if !getCopyFlag || nameFlag != "github" {
		t.Fatalf("expected getCopyFlag=true and nameFlag='github', got %v and %q", getCopyFlag, nameFlag)
	}

	if err := addCmd.Flags().Parse([]string{"--copy"}); err != nil {
		t.Fatalf("unexpected parse error on addCmd --copy: %v", err)
	}
	if !addCopyFlag {
		t.Fatalf("expected addCopyFlag=true after parsing --copy")
	}
}

func TestHandleGetOutputDefault(t *testing.T) {
	oldWrite := clipboardWriteAll
	defer func() { clipboardWriteAll = oldWrite }()

	called := false
	clipboardWriteAll = func(text string) error {
		called = true
		return nil
	}

	passwords := map[string]string{"github": "s3cr3t"}
	var gotErr error
	out := captureStdout(t, func() {
		gotErr = handleGetOutput("github", passwords, false)
	})

	if gotErr != nil {
		t.Fatalf("expected nil error, got %v", gotErr)
	}
	if called {
		t.Fatalf("expected clipboard not to be called when copy flag is false")
	}
	if out != "github:s3cr3t" {
		t.Fatalf("expected output 'github:s3cr3t', got %q", out)
	}
}

func TestHandleGetOutputCopySuccess(t *testing.T) {
	oldWrite := clipboardWriteAll
	defer func() { clipboardWriteAll = oldWrite }()

	var copied string
	clipboardWriteAll = func(text string) error {
		copied = text
		return nil
	}

	passwords := map[string]string{"github": "s3cr3t"}
	var gotErr error
	out := captureStdout(t, func() {
		gotErr = handleGetOutput("github", passwords, true)
	})

	if gotErr != nil {
		t.Fatalf("expected nil error, got %v", gotErr)
	}
	if copied != "s3cr3t" {
		t.Fatalf("expected 's3cr3t' copied to clipboard, got %q", copied)
	}
	if strings.Contains(out, "s3cr3t") {
		t.Fatalf("expected secret not to be printed to stdout, got %q", out)
	}
	if out != "" {
		t.Fatalf("expected empty stdout when copying to clipboard, got %q", out)
	}
}

func TestHandleGetOutputCopyError(t *testing.T) {
	oldWrite := clipboardWriteAll
	defer func() { clipboardWriteAll = oldWrite }()

	clipErr := errors.New("clipboard unavailable")
	clipboardWriteAll = func(text string) error {
		return clipErr
	}

	passwords := map[string]string{"github": "s3cr3t"}
	var gotErr error
	out := captureStdout(t, func() {
		gotErr = handleGetOutput("github", passwords, true)
	})

	if !errors.Is(gotErr, clipErr) {
		t.Fatalf("expected error wrapping %v, got %v", clipErr, gotErr)
	}
	if !strings.Contains(gotErr.Error(), "failed to copy password to clipboard: clipboard unavailable") {
		t.Fatalf("expected wrapped error message, got %q", gotErr.Error())
	}
	if !strings.Contains(out, "failed to copy password to clipboard: clipboard unavailable") {
		t.Fatalf("expected clear error message, got %q", out)
	}
	if strings.Contains(out, "s3cr3t") {
		t.Fatalf("expected secret not to be printed to stdout on error, got %q", out)
	}
}

func TestHandleGetOutputEmptyAndMissingKeys(t *testing.T) {
	oldWrite := clipboardWriteAll
	defer func() { clipboardWriteAll = oldWrite }()

	called := false
	clipboardWriteAll = func(text string) error {
		called = true
		return nil
	}

	var gotErr error
	outEmpty := captureStdout(t, func() {
		gotErr = handleGetOutput("github", map[string]string{}, true)
	})
	if gotErr != nil {
		t.Fatalf("expected nil error for empty savedPasswords, got %v", gotErr)
	}
	if called {
		t.Fatalf("expected clipboard not to be called when savedPasswords is empty")
	}
	if !strings.Contains(outEmpty, "No passwords saved with ") {
		t.Fatalf("expected empty passwords message, got %q", outEmpty)
	}

	outNil := captureStdout(t, func() {
		gotErr = handleGetOutput("github", nil, true)
	})
	if gotErr != nil {
		t.Fatalf("expected nil error for nil savedPasswords, got %v", gotErr)
	}
	if called {
		t.Fatalf("expected clipboard not to be called when savedPasswords is nil")
	}
	if !strings.Contains(outNil, "No passwords saved with ") {
		t.Fatalf("expected empty passwords message for nil map, got %q", outNil)
	}

	outMissing := captureStdout(t, func() {
		gotErr = handleGetOutput("gitlab", map[string]string{"github": "s3cr3t"}, true)
	})
	if gotErr != nil {
		t.Fatalf("expected nil error for missing key, got %v", gotErr)
	}
	if called {
		t.Fatalf("expected clipboard not to be called when key is missing")
	}
	if outMissing != "Password with key 'gitlab' not found" {
		t.Fatalf("expected not found message, got %q", outMissing)
	}
}

func TestCopyPasswordToClipboard(t *testing.T) {
	oldWrite := clipboardWriteAll
	defer func() { clipboardWriteAll = oldWrite }()

	var got string
	clipboardWriteAll = func(text string) error {
		got = text
		return nil
	}

	out := captureStdout(t, func() {
		if err := copyPasswordToClipboard("new-pass-123"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
	if got != "new-pass-123" {
		t.Fatalf("expected 'new-pass-123' written to clipboard, got %q", got)
	}
	if out != "" {
		t.Fatalf("expected no output on success, got %q", out)
	}

	clipErr := errors.New("no display")
	clipboardWriteAll = func(text string) error {
		return clipErr
	}
	var gotErr error
	outErr := captureStdout(t, func() {
		gotErr = copyPasswordToClipboard("new-pass-123")
		if gotErr == nil {
			t.Fatalf("expected error when clipboard write fails")
		}
	})
	if !errors.Is(gotErr, clipErr) {
		t.Fatalf("expected error wrapping %v, got %v", clipErr, gotErr)
	}
	if !strings.Contains(outErr, "failed to copy password to clipboard: no display") {
		t.Fatalf("expected clear error message, got %q", outErr)
	}
	if strings.Contains(outErr, "new-pass-123") {
		t.Fatalf("expected secret not to appear in error output, got %q", outErr)
	}
}
