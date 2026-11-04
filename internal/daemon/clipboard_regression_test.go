package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCopyPasswordToClipboard_RetryPreservesExternallyChangedContent(t *testing.T) {
	h := newReadFailureHarness(t, 1)
	h.callbacks[0]()
	if len(h.callbacks) != 2 {
		t.Fatalf("expected retry after failed read, got %d callbacks", len(h.callbacks))
	}
	h.clipboard = "external-content"
	h.callbacks[1]()
	if h.clipboard != "external-content" || h.reads != 2 {
		t.Fatalf("retry must verify content before clearing: clipboard %q, reads %d", h.clipboard, h.reads)
	}
	if len(h.callbacks) != 2 {
		t.Fatal("successful read of changed content must not schedule another retry")
	}
}

func TestCopyPasswordToClipboard_ExhaustedReadRetriesDoNotClearUnverified(t *testing.T) {
	h := newReadFailureHarness(t, 1000)
	clipboardClearRetryDelays = nil // Exercise the zero-retry boundary.
	writes := 0
	writeClipboard = func(string) error { writes++; return nil }
	h.callbacks[0]()
	if h.reads != 1 || len(h.callbacks) != 1 {
		t.Fatalf("expected one attempt and no retry, reads %d callbacks %d", h.reads, len(h.callbacks))
	}
	if writes != 0 {
		t.Fatalf("unverified clipboard must not be cleared, got %d writes", writes)
	}
	if len(h.reported) != 1 {
		t.Fatalf("expected one failure report, got %v", h.reported)
	}
	err := h.reported[0]
	if !errors.Is(err, errReadFailure) {
		t.Fatalf("report must preserve the read failure: %v", err)
	}
	if !strings.Contains(err.Error(), "may still be on the clipboard") {
		t.Fatalf("report must warn about retained secret: %v", err)
	}
}

func TestCopyPasswordToClipboard_UnhintedTimeoutBoundaries(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Nanosecond, time.Nanosecond, UnhintedClipboardClearTimeout, UnhintedClipboardClearTimeout + time.Nanosecond} {
		t.Run(timeout.String(), func(t *testing.T) {
			h := newReadFailureHarness(t, 0)
			clipboardOS = "freebsd"
			clipboardClearTimeout = timeout
			if err := copyPasswordToClipboard("secret123"); err != nil {
				t.Fatal(err)
			}
			want := timeout
			if timeout <= 0 || timeout > UnhintedClipboardClearTimeout {
				want = UnhintedClipboardClearTimeout
			}
			if len(h.delays) != 2 || h.delays[1] != want {
				t.Fatalf("expected effective timeout %v, got %v", want, h.delays)
			}
			wantReports := 0
			if timeout <= 0 {
				wantReports = 1
			}
			if len(h.reported) != wantReports {
				t.Fatalf("expected %d configuration warnings, got %v", wantReports, h.reported)
			}
			h.callbacks[1]()
			if h.clipboard != "" {
				t.Fatal("effective expiry did not clear the secret")
			}
		})
	}
}
