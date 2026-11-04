package daemon

import (
	"errors"
	"strings"
	"testing"
)

func TestFailedCopyReadFailurePreservesContentAndBothErrors(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatal(err)
	}
	writeErr, readErr := errors.New("write unavailable"), errors.New("read unavailable")
	clears := 0
	writeClipboard = func(text string) error {
		if text == "" {
			clears++
			return h.write(text)
		}
		return writeErr
	}
	readClipboard = func() (string, error) { return "", readErr }
	err := copyPasswordToClipboard("new-secret")
	if !errors.Is(err, writeErr) || !errors.Is(err, readErr) {
		t.Fatalf("expected both underlying errors, got %v", err)
	}
	if !strings.Contains(err.Error(), "write password to clipboard") || !strings.Contains(err.Error(), "may still be on the clipboard") {
		t.Fatalf("missing write context or retained-password warning: %v", err)
	}
	if got, _ := h.read(); got != "old-secret" || clears != 0 {
		t.Fatalf("unverified content must remain: content %q, clears %d", got, clears)
	}
}

func TestFailedCopyVerificationDoesNotEraseNewerCopy(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatal(err)
	}
	writeErr := errors.New("write unavailable")
	writeClipboard = func(text string) error {
		if text == "failed-secret" {
			return writeErr
		}
		return h.write(text)
	}
	var newerErr error
	readClipboard = func() (string, error) {
		snapshot, err := h.read()
		// Complete a newer copy after the failed copy's verification snapshot,
		// before its final token check. No sleeps or goroutine ordering needed.
		newerErr = copyPasswordToClipboard("newer-secret")
		return snapshot, err
	}
	if err := copyPasswordToClipboard("failed-secret"); !errors.Is(err, writeErr) {
		t.Fatalf("expected original write error, got %v", err)
	}
	if newerErr != nil {
		t.Fatal(newerErr)
	}
	if got, _ := h.read(); got != "newer-secret" {
		t.Fatalf("failed copy erased newer content: %q", got)
	}
	readClipboard = h.read
	h.mu.Lock()
	callbacks := append([]func(){}, h.callbacks...)
	h.mu.Unlock()
	for _, clear := range callbacks {
		clear()
	}
	if got, _ := h.read(); got != "" {
		t.Fatalf("newer copy lost its auto-clear: %q", got)
	}
}
