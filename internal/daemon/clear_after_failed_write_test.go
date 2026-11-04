package daemon

import (
	"errors"
	"testing"
)

// failFirstClear makes the first clearing write fail, then delegates to h.
func failFirstClear(h *concurrentClipboardHarness) {
	failed := false
	writeClipboard = func(text string) error {
		if text == "" && !failed {
			failed = true
			return errors.New("clipboard busy")
		}
		return h.write(text)
	}
}

func runOnlyCallback(t *testing.T, h *concurrentClipboardHarness, want int) {
	t.Helper()
	h.mu.Lock()
	callbacks := append([]func(){}, h.callbacks...)
	h.mu.Unlock()
	if len(callbacks) != want {
		t.Fatalf("expected %d scheduled callbacks, got %d", want, len(callbacks))
	}
	callbacks[want-1]()
}

// A transient failure of the clearing write must schedule a retry that
// clears the password, instead of leaving it on the clipboard.
func TestFailedClearWriteIsRetried(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	failFirstClear(h)

	runOnlyCallback(t, h, 1)
	if got, _ := h.read(); got != "secret" {
		t.Fatalf("precondition: expected password after failed clear, got %q", got)
	}
	runOnlyCallback(t, h, 2)
	if got, _ := h.read(); got != "" {
		t.Fatalf("expected retry to clear password, got %q", got)
	}
}

// The best-effort clear after a failed copy must also be retried when its
// clearing write fails.
func TestFailedClearAfterFailedCopyIsRetried(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	failedClear := false
	writeClipboard = func(text string) error {
		switch {
		case text == "new-secret":
			return errors.New("clipboard unavailable")
		case text == "" && !failedClear:
			failedClear = true
			return errors.New("clipboard busy")
		}
		return h.write(text)
	}
	if err := copyPasswordToClipboard("new-secret"); err == nil {
		t.Fatal("expected write error")
	}
	if got, _ := h.read(); got != "old-secret" {
		t.Fatalf("precondition: expected old password to remain, got %q", got)
	}
	runOnlyCallback(t, h, 2)
	if got, _ := h.read(); got != "" {
		t.Fatalf("expected retry to clear old password, got %q", got)
	}
}

// Clearing-write retries are bounded by clipboardClearRetryDelays.
func TestFailedClearWriteRetriesAreBounded(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	clipboardClearRetryDelays = clipboardClearRetryDelays[:1]
	if err := copyPasswordToClipboard("secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	writeClipboard = func(text string) error {
		if text == "" {
			return errors.New("clipboard busy")
		}
		return h.write(text)
	}
	runOnlyCallback(t, h, 1)
	runOnlyCallback(t, h, 2)
	h.mu.Lock()
	n := len(h.callbacks)
	h.mu.Unlock()
	if n != 2 {
		t.Fatalf("expected no retry after the last attempt, got %d callbacks", n)
	}
}
