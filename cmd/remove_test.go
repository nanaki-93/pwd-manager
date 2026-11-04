package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

// captureRemoveStdout reuses captureStdout, which drains the pipe in a
// goroutine started before fn runs, closes both pipe ends on every exit path
// (including t.Fatal / runtime.Goexit) and restores os.Stdout.
func captureRemoveStdout(t *testing.T, fn func()) string {
	t.Helper()
	return captureStdout(t, fn)
}

func runRemovePasswordWithCapture(t *testing.T, name string, saved map[string]string, saveErr error) (string, bool, error) {
	t.Helper()
	called := false
	var err error
	out := captureRemoveStdout(t, func() {
		err = removePassword(name, saved, func() error {
			called = true
			return saveErr
		})
	})
	return out, called, err
}

func TestRemovePasswordEmptyOrMissing(t *testing.T) {
	assertNotFound := func(t *testing.T, err error, called bool, out string) {
		t.Helper()
		if !errors.Is(err, errPasswordNotFound) || !strings.Contains(err.Error(), `"github"`) {
			t.Fatalf("expected not-found error naming the key, got %v", err)
		}
		if called || out != "" {
			t.Fatalf("called=%v out=%q", called, out)
		}
	}

	t.Run("no passwords saved", func(t *testing.T) {
		out, called, err := runRemovePasswordWithCapture(t, "github", map[string]string{}, nil)
		assertNotFound(t, err, called, out)
	})

	t.Run("nil passwords map", func(t *testing.T) {
		out, called, err := runRemovePasswordWithCapture(t, "github", nil, nil)
		assertNotFound(t, err, called, out)
	})

	t.Run("password key not found", func(t *testing.T) {
		saved := map[string]string{"email": "secret"}
		out, called, err := runRemovePasswordWithCapture(t, "github", saved, nil)
		assertNotFound(t, err, called, out)
		if len(saved) != 1 || saved["email"] != "secret" {
			t.Fatalf("expected existing entries untouched, got %v", saved)
		}
	})
}

func TestRemovePasswordSuccess(t *testing.T) {
	saved := map[string]string{"github": "secret", "email": "keep"}
	called := false
	var err error
	out := captureRemoveStdout(t, func() {
		err = removePassword("github", saved, func() error {
			called = true
			if _, exists := saved["github"]; exists {
				t.Fatal("expected key to be deleted before save is invoked")
			}
			return nil
		})
	})
	if err != nil || !called {
		t.Fatalf("err=%v called=%v", err, called)
	}
	if _, exists := saved["github"]; exists || saved["email"] != "keep" {
		t.Fatalf("unexpected map state: %v", saved)
	}
	if out != "github removed\n" {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestRemovePasswordPersistenceFailure(t *testing.T) {
	t.Run("does not print success and restores entry", func(t *testing.T) {
		saved := map[string]string{"github": "secret"}
		saveErr := errors.New("disk full")
		out, _, err := runRemovePasswordWithCapture(t, "github", saved, saveErr)
		if !errors.Is(err, saveErr) {
			t.Fatalf("expected wrapped saveErr, got %v", err)
		}
		if strings.Contains(out, "removed") || out != "" {
			t.Fatalf("expected empty stdout on save failure, got %q", out)
		}
		if saved["github"] != "secret" {
			t.Fatalf("expected map entry to be restored on save failure, got %q", saved["github"])
		}
	})

	t.Run("removeFromVault propagates save error", func(t *testing.T) {
		orig := saveVault
		t.Cleanup(func() { saveVault = orig })
		saveErr := errors.New("disk full")
		var gotIn error = errors.New("unset")
		saveVault = func(_ model.PwdFile, in error) error {
			gotIn = in
			return saveErr
		}
		pwdObj := model.PwdFile{SavedPasswords: map[string]string{"github": "secret"}}
		var err error
		out := captureRemoveStdout(t, func() { err = removeFromVault(pwdObj, "github") })
		if !errors.Is(err, saveErr) || out != "" {
			t.Fatalf("expected wrapped saveErr and no output, err=%v out=%q", err, out)
		}
		if gotIn != nil {
			t.Fatalf("expected nil save input error, got %v", gotIn)
		}
		if pwdObj.SavedPasswords["github"] != "secret" {
			t.Fatalf("expected entry restored, got %v", pwdObj.SavedPasswords)
		}
	})

	t.Run("restores empty password value", func(t *testing.T) {
		saved := map[string]string{"empty-val": ""}
		saveErr := errors.New("write error")
		out, _, err := runRemovePasswordWithCapture(t, "empty-val", saved, saveErr)
		if !errors.Is(err, saveErr) || out != "" {
			t.Fatalf("err=%v out=%q", err, out)
		}
		if val, exists := saved["empty-val"]; !exists || val != "" {
			t.Fatalf("expected empty-value entry to be restored, exists=%v val=%q", exists, val)
		}
	})
}
