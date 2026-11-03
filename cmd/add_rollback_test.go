package cmd

import (
	"errors"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

func TestStorePasswordRollsBackMapOnSaveFailure(t *testing.T) {
	orig := saveVault
	t.Cleanup(func() { saveVault = orig })

	saveErr := errors.New("disk full")
	saveVault = func(p model.PwdFile, _ error) error {
		if got := p.SavedPasswords["github"]; got != "new-secret" {
			t.Fatalf("expected new value passed to save, got %q", got)
		}
		return saveErr
	}

	for _, tc := range []struct {
		name    string
		initial map[string]string
	}{
		{name: "overwrite restores previous value", initial: map[string]string{"email": "keep-me", "github": "old-secret"}},
		{name: "new key is removed", initial: map[string]string{"email": "keep-me"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := make(map[string]string, len(tc.initial))
			for k, v := range tc.initial {
				want[k] = v
			}
			pwdObj := model.PwdFile{MasterPassword: "hashed-master", SavedPasswords: tc.initial}

			err := storePassword(pwdObj, "github", "new-secret")
			if !errors.Is(err, saveErr) {
				t.Fatalf("expected wrapped save error, got %v", err)
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

func TestStorePasswordKeepsValueOnSaveSuccess(t *testing.T) {
	orig := saveVault
	t.Cleanup(func() { saveVault = orig })
	saveVault = func(model.PwdFile, error) error { return nil }

	pwdObj := model.PwdFile{SavedPasswords: map[string]string{"github": "old-secret"}}
	if err := storePassword(pwdObj, "github", "new-secret"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got := pwdObj.SavedPasswords["github"]; got != "new-secret" {
		t.Fatalf("expected new value after successful save, got %q", got)
	}
}
