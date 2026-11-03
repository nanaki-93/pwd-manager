package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

func TestReadPwdNameRejectsOverlongUnicodeAtEOF(t *testing.T) {
	name, err := readPwdName(strings.NewReader(strings.Repeat("é", maxPwdNameLen+1)))
	if name != "" || !errors.Is(err, errInvalidPwdName) {
		t.Fatalf("expected overlong Unicode name rejected at EOF, got %q, %v", name, err)
	}
}

func TestStorePasswordRollbackPreservesEmptyValuePresence(t *testing.T) {
	original := saveVault
	t.Cleanup(func() { saveVault = original })
	saveErr := errors.New("save failed")
	saveVault = func(model.PwdFile, error) error { return saveErr }
	vault := model.PwdFile{SavedPasswords: map[string]string{"entry": ""}}
	if err := storePassword(vault, "entry", "replacement"); !errors.Is(err, saveErr) {
		t.Fatalf("expected wrapped save error, got %v", err)
	}
	if value, exists := vault.SavedPasswords["entry"]; !exists || value != "" {
		t.Fatalf("rollback lost preexisting empty value: value=%q present=%v", value, exists)
	}
}

func TestAddPromptedPasswordWipesOnClearFailureAndKeepsSavedValue(t *testing.T) {
	oldSave, oldClear := saveVault, clipboardClearer
	t.Cleanup(func() { saveVault, clipboardClearer = oldSave, oldClear })
	saveVault = func(model.PwdFile, error) error { return nil }
	content := fakeClipboard(t, nil, nil)
	clearErr := errors.New("clear failed")
	clipboardClearer = func(string) error { return clearErr }
	secret := []byte("dummy-secret")
	vault := model.PwdFile{SavedPasswords: map[string]string{}}
	err := addPromptedPassword(vault, "entry", secret, true)
	if !errors.Is(err, clearErr) {
		t.Fatalf("expected wrapped clear error, got %v", err)
	}
	assertWiped(t, secret)
	if vault.SavedPasswords["entry"] != "dummy-secret" || *content != "dummy-secret" {
		t.Fatal("clear failure must not roll back a successful save or corrupt the copied value")
	}
}

func TestClearClipboardAfterPreservesBothFailures(t *testing.T) {
	readErr, writeErr := errors.New("read failed"), errors.New("write failed")
	content := fakeClipboard(t, readErr, writeErr)
	*content = "dummy-secret"
	err := clearClipboardAfter(context.Background(), "dummy-secret", 0)
	if !errors.Is(err, readErr) || !errors.Is(err, writeErr) {
		t.Fatalf("expected both clipboard failures wrapped, got %v", err)
	}
	if *content != "dummy-secret" {
		t.Fatal("failed clipboard write unexpectedly changed content")
	}
}
