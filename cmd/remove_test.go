package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func captureRemoveStdout(t *testing.T, fn func()) string {
	t.Helper()
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = origStdout
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close stdout writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read stdout pipe: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("failed to close stdout reader: %v", err)
	}
	return buf.String()
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
	t.Run("no passwords saved", func(t *testing.T) {
		out, called, err := runRemovePasswordWithCapture(t, "github", map[string]string{}, nil)
		if err != nil || called || out != "No passwords saved\n" {
			t.Fatalf("err=%v called=%v out=%q", err, called, out)
		}
	})

	t.Run("nil passwords map", func(t *testing.T) {
		out, called, err := runRemovePasswordWithCapture(t, "github", nil, nil)
		if err != nil || called || out != "No passwords saved\n" {
			t.Fatalf("err=%v called=%v out=%q", err, called, out)
		}
	})

	t.Run("password key not found", func(t *testing.T) {
		saved := map[string]string{"email": "secret"}
		out, called, err := runRemovePasswordWithCapture(t, "github", saved, nil)
		if err != nil || called || saved["email"] != "secret" {
			t.Fatalf("err=%v called=%v saved=%v", err, called, saved)
		}
		if out != "Password with key 'github' not found\n" {
			t.Fatalf("unexpected output %q", out)
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
