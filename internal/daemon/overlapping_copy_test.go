package daemon

import (
	"sync"
	"testing"
)

// An older copy whose write lands after a newer copy's write must still be
// removed by the scheduled clear instead of staying on the clipboard forever.
func TestCopyPasswordToClipboard_OverlappingCopyOlderWriteLandsLastIsCleared(t *testing.T) {
	resetClipboardTestState(t)
	t.Cleanup(func() {
		clipboardMu.Lock()
		clipboardStalePwds = nil
		clipboardMu.Unlock()
	})
	h := newConcurrentClipboardHarness()

	oldWriteStarted := make(chan struct{})
	releaseOldWrite := make(chan struct{})
	writeClipboard = func(text string) error {
		if text == "old-secret" {
			close(oldWriteStarted)
			<-releaseOldWrite
		}
		return h.write(text)
	}
	release := sync.OnceFunc(func() { close(releaseOldWrite) })
	t.Cleanup(release)

	oldDone := make(chan error, 1)
	go func() { oldDone <- copyPasswordToClipboard("old-secret") }()
	<-oldWriteStarted

	if err := copyPasswordToClipboard("new-secret"); err != nil {
		t.Fatalf("unexpected error from newer copy: %v", err)
	}
	release()
	if err := <-oldDone; err != nil {
		t.Fatalf("unexpected error from older copy: %v", err)
	}

	if got, _ := h.read(); got != "old-secret" {
		t.Fatalf("precondition: expected older write to land last, got %q", got)
	}
	h.mu.Lock()
	callbacks := append([]func(){}, h.callbacks...)
	h.mu.Unlock()
	if len(callbacks) == 0 {
		t.Fatal("expected a clear to be scheduled")
	}
	for _, cb := range callbacks {
		cb()
	}
	if got, _ := h.read(); got != "" {
		t.Fatalf("expected scheduled clear to remove the password left on the clipboard, got %q", got)
	}
}
