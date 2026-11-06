package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
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

func TestAddPromptedPasswordReportsClearFailure(t *testing.T) {
	origSave, origClearer := saveVault, clipboardClearer
	t.Cleanup(func() { saveVault, clipboardClearer = origSave, origClearer })
	saveVault = func(model.PwdFile, error) error { return nil }
	fakeClipboard(t, nil, nil)
	clearErr := errors.New("clear failed")
	clipboardClearer = func(string) error { return clearErr }

	err := addPromptedPassword(model.PwdFile{}, "github", []byte("s3cret"), true)
	if !errors.Is(err, clearErr) || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("expected wrapped clear error without secret, got %v", err)
	}
}

func TestVerifyAndClearClipboard(t *testing.T) {
	readErr := errors.New("read failed")
	writeErr := errors.New("write failed")
	for _, tc := range []struct {
		name       string
		initial    string
		readErr    error
		writeErr   error
		want       string
		wantErr    error
		wantNilErr bool
	}{
		{name: "clears when still holding secret", initial: "s3cret", want: "", wantNilErr: true},
		{name: "keeps value the user copied since", initial: "other", want: "other", wantNilErr: true},
		{name: "unreadable clipboard cleared anyway", initial: "s3cret", readErr: readErr, want: "", wantErr: readErr},
		{name: "clear failure reported", initial: "s3cret", writeErr: writeErr, want: "s3cret", wantErr: writeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := fakeClipboard(t, tc.readErr, tc.writeErr)
			*content = tc.initial
			err := verifyAndClearClipboard("s3cret")
			if tc.wantNilErr && err != nil || !tc.wantNilErr && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
			if *content != tc.want {
				t.Fatalf("expected clipboard %q, got %q", tc.want, *content)
			}
		})
	}
}
