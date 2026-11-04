package daemon

import "testing"

// A copy that completes after the expiry clear read the clipboard (but
// before the clear takes clipboardClearMu) must not have its content erased
// by that clear, even though the clear's snapshot still shows the password.
func TestClearClipboard_CopyAfterReadIsNotErased(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h.mu.Lock()
	clear := h.callbacks[0]
	h.mu.Unlock()

	var copyErr error
	readClipboard = func() (string, error) {
		snapshot, err := h.read()
		// No lock is held during the read, so the copy completes here,
		// deterministically between the read and the clearing write.
		copyErr = copyPasswordToClipboard("new-content")
		return snapshot, err
	}
	clear()
	if copyErr != nil {
		t.Fatalf("unexpected error from new copy: %v", copyErr)
	}
	if got, _ := h.read(); got != "new-content" {
		t.Fatalf("clear erased content copied after its read: got %q", got)
	}
}

// While the clear writes, clipboardClearMu is held, so no copy can start
// between the clear's final token check and its write.
func TestClearClipboard_HoldsClearLockDuringWrite(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h.mu.Lock()
	clear := h.callbacks[0]
	h.mu.Unlock()

	lockedDuringWrite := false
	writeClipboard = func(text string) error {
		if text == "" {
			if clipboardClearMu.TryLock() {
				clipboardClearMu.Unlock()
			} else {
				lockedDuringWrite = true
			}
		}
		return h.write(text)
	}
	clear()
	if !lockedDuringWrite {
		t.Fatal("clipboardClearMu must be held while the clear writes")
	}
	if got, _ := h.read(); got != "" {
		t.Fatalf("expected password cleared, got %q", got)
	}
}
