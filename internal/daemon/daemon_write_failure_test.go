package daemon

import (
	"errors"
	"strings"
	"testing"
)

// A failed copy cancels the earlier password's pending clear, so it must
// clear that password itself instead of leaving it on the clipboard.
func TestCopyPasswordToClipboard_FailedWriteClearsPreviousPassword(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	writeErr := errors.New("clipboard unavailable")
	writeClipboard = func(text string) error {
		if text != "" {
			return writeErr
		}
		return h.write(text)
	}
	err := copyPasswordToClipboard("new-secret")
	if !errors.Is(err, writeErr) || !strings.Contains(err.Error(), "write password to clipboard") {
		t.Fatalf("expected wrapped write error, got %v", err)
	}
	if got, _ := h.read(); got != "" {
		t.Fatalf("expected previous password to be cleared, got %q", got)
	}
}

func TestCopyPasswordToClipboard_FailedWriteReportsFailedClear(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	writeErr := errors.New("clipboard unavailable")
	clearErr := errors.New("clear refused")
	writeClipboard = func(text string) error {
		if text == "" {
			return clearErr
		}
		return writeErr
	}
	err := copyPasswordToClipboard("new-secret")
	if !errors.Is(err, writeErr) || !errors.Is(err, clearErr) {
		t.Fatalf("expected write and clear errors, got %v", err)
	}
	if !strings.Contains(err.Error(), "write password to clipboard") {
		t.Fatalf("expected write context, got %v", err)
	}
	if got, _ := h.read(); got != "old-secret" {
		t.Fatalf("precondition: expected old password to remain, got %q", got)
	}
}

// Without an earlier pending clear there is nothing to remove, so a failed
// write must not touch the clipboard.
func TestCopyPasswordToClipboard_FailedFirstWriteDoesNotClear(t *testing.T) {
	resetClipboardTestState(t)
	writes := 0
	writeErr := errors.New("clipboard unavailable")
	writeClipboard = func(string) error {
		writes++
		return writeErr
	}
	if err := copyPasswordToClipboard("secret"); !errors.Is(err, writeErr) {
		t.Fatalf("expected write error, got %v", err)
	}
	if writes != 1 {
		t.Fatalf("expected only the password write, got %d writes", writes)
	}
}
