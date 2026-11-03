package cmd

import (
	"errors"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

func assertWiped(t *testing.T, b []byte) {
	t.Helper()
	for i, c := range b {
		if c != 0 {
			t.Fatalf("prompted password bytes not wiped at index %d: %q", i, b)
		}
	}
}

func TestAddPromptedPasswordWipesBytesOnEveryPath(t *testing.T) {
	origSave, origClip := saveVault, clipboardWriteAll
	t.Cleanup(func() { saveVault, clipboardWriteAll = origSave, origClip })

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
