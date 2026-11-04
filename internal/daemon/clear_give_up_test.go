package daemon

import (
	"errors"
	"strings"
	"testing"
)

func giveUpWithBusyReads(t *testing.T, writeErr error) (*concurrentClipboardHarness, []string) {
	t.Helper()
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	clipboardClearRetryDelays = nil
	var alerts []string
	notifyClipboardClearFailure = func(msg string) error { alerts = append(alerts, msg); return nil }
	if err := copyPasswordToClipboard("secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	readClipboard = func() (string, error) { return "", errors.New("clipboard busy") }
	if writeErr != nil {
		writeClipboard = func(text string) error {
			if text == "" {
				return writeErr
			}
			return h.write(text)
		}
	}
	runOnlyCallback(t, h, 1)
	return h, alerts
}

// Persistent read failures must not leave the password on the clipboard:
// the clear falls back to an unverified write and the user is alerted.
func TestReadFailureGiveUpForcesClearAndAlerts(t *testing.T) {
	h, alerts := giveUpWithBusyReads(t, nil)
	if h.clearWrites != 1 || h.currentClipboard != "" {
		t.Fatalf("expected forced clear, clipboard %q clears %d", h.currentClipboard, h.clearWrites)
	}
	if len(alerts) != 1 || !strings.Contains(alerts[0], "cleared") {
		t.Fatalf("expected one visible alert, got %v", alerts)
	}
}

func TestReadFailureGiveUpAlertsWhenForcedClearFails(t *testing.T) {
	h, alerts := giveUpWithBusyReads(t, errors.New("clipboard locked"))
	if h.currentClipboard != "secret" {
		t.Fatalf("precondition: expected password to remain, got %q", h.currentClipboard)
	}
	if len(alerts) != 1 || !strings.Contains(alerts[0], "may still be") {
		t.Fatalf("expected one visible alert about the remaining password, got %v", alerts)
	}
}

func TestReadFailureGiveUpSkipsNewerCopy(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	clipboardClearRetryDelays = nil
	if err := copyPasswordToClipboard("old"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h.mu.Lock()
	stale := h.callbacks[0]
	h.mu.Unlock()
	if err := copyPasswordToClipboard("new"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	readClipboard = func() (string, error) { return "", errors.New("clipboard busy") }
	handleClearReadFailure(1, "old", 0, errors.New("clipboard busy"))
	stale()
	if got, _ := h.read(); got != "new" {
		t.Fatalf("forced clear erased newer copy: %q", got)
	}
}
