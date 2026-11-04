package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFailedCopyReadRetriesUseConfiguredDelays(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	clipboardClearRetryDelays = []time.Duration{17 * time.Millisecond, 43 * time.Millisecond}
	var delays []time.Duration
	schedule := afterFunc
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		delays = append(delays, d)
		return schedule(d, f)
	}
	if err := copyPasswordToClipboard("old"); err != nil {
		t.Fatal(err)
	}
	writeErr, readErr := errors.New("copy unavailable"), errors.New("read unavailable")
	writeClipboard = func(text string) error {
		if text == "new" {
			return writeErr
		}
		return h.write(text)
	}
	readClipboard = func() (string, error) { return "", readErr }
	var reports []error
	reportClipboardClearFailure = func(err error) { reports = append(reports, err) }
	alerts := 0
	notifyClipboardClearFailure = func(string) error { alerts++; return nil }
	err := copyPasswordToClipboard("new")
	if !errors.Is(err, writeErr) || !errors.Is(err, readErr) {
		t.Fatalf("copy must preserve both errors: %v", err)
	}
	if len(delays) != 2 || delays[1] != clipboardClearRetryDelays[0] {
		t.Fatalf("first retry delay: %v", delays)
	}
	runOnlyCallback(t, h, 2)
	if len(delays) != 3 || delays[2] != clipboardClearRetryDelays[1] {
		t.Fatalf("second retry delay: %v", delays)
	}
	if h.clearWrites != 0 || alerts != 0 {
		t.Fatal("fallback or alert occurred before retries were exhausted")
	}
	runOnlyCallback(t, h, 3)
	if len(delays) != 3 || h.clearWrites != 1 || alerts != 1 {
		t.Fatalf("expected bounded retries, one fallback and alert: delays %v clears %d alerts %d", delays, h.clearWrites, alerts)
	}
	requireFinalReadFailure(t, reports, readErr)
	requireNoStalePwds(t)
}

func requireFinalReadFailure(t *testing.T, reports []error, cause error) {
	t.Helper()
	if len(reports) != 2 || !errors.Is(reports[1], cause) || !strings.Contains(reports[1].Error(), "giving up") {
		t.Fatalf("expected final wrapped read failure report: %v", reports)
	}
}

func TestReadFailureGiveUpReportsNotificationFailure(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	clipboardClearRetryDelays = nil
	readErr, notifyErr := errors.New("read unavailable"), errors.New("notification unavailable")
	var reports []error
	reportClipboardClearFailure = func(err error) { reports = append(reports, err) }
	notifyClipboardClearFailure = func(string) error { return notifyErr }
	if err := copyPasswordToClipboard("secret"); err != nil {
		t.Fatal(err)
	}
	readClipboard = func() (string, error) { return "", readErr }
	runOnlyCallback(t, h, 1)
	if len(reports) != 2 || !errors.Is(reports[0], readErr) || !errors.Is(reports[1], notifyErr) {
		t.Fatalf("expected clear and notification failure reports preserving causes: %v", reports)
	}
	if got, _ := h.read(); got != "" || h.clearWrites != 1 {
		t.Fatalf("notification failure must not prevent fallback: clipboard %q clears %d", got, h.clearWrites)
	}
}
