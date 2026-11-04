package daemon

import (
	"testing"
	"time"
)

// A copy that starts after the expiry clear verified the clipboard must not
// have its new content erased by that clear's write.
func TestClearClipboard_CopyStartingDuringClearIsNotErased(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	copyDone := make(chan error, 1)
	writeClipboard = func(text string) error {
		if text == "" {
			// Start a new copy after the clear checked the token but before
			// its write lands, and give that copy time to race ahead.
			go func() { copyDone <- copyPasswordToClipboard("new-content") }()
			time.Sleep(50 * time.Millisecond)
		}
		return h.write(text)
	}

	h.mu.Lock()
	clear := h.callbacks[0]
	h.mu.Unlock()
	clear()
	if err := <-copyDone; err != nil {
		t.Fatalf("unexpected error from new copy: %v", err)
	}
	if got, _ := h.read(); got != "new-content" {
		t.Fatalf("clear erased content copied after its check: got %q", got)
	}
}
