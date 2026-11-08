package daemon

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func resetClipboardTestState(t *testing.T) {
	t.Helper()
	origWrite, origRead, origNotify := writeClipboard, readClipboard, notifyClipboardClearFailure
	notifyClipboardClearFailure = func(string) error { return nil }
	origAfter := afterFunc
	origTimeout := clipboardClearTimeout
	origOS := clipboardOS
	origConcealedWrite := writeConcealedClipboard
	writeConcealedClipboard = nil // never touch the real clipboard natively
	origReport := reportClipboardClearFailure
	origRetryDelays := clipboardClearRetryDelays
	reportClipboardClearFailure = func(error) {}

	t.Cleanup(func() {
		clipboardMu.Lock()
		if clipboardTimer != nil {
			clipboardTimer.Stop()
			clipboardTimer = nil
		}
		clipboardToken, clipboardStalePwds, clipboardOwned, clipboardActivePwd = 0, nil, false, ""
		clipboardMu.Unlock()
		writeClipboard, readClipboard, notifyClipboardClearFailure = origWrite, origRead, origNotify
		afterFunc = origAfter
		clipboardClearTimeout = origTimeout
		clipboardOS = origOS
		writeConcealedClipboard = origConcealedWrite
		reportClipboardClearFailure = origReport
		clipboardClearRetryDelays = origRetryDelays
	})
}

func TestCopyPasswordToClipboard_WriteError(t *testing.T) {
	resetClipboardTestState(t)

	expectedErr := errors.New("clipboard unavailable")
	writeClipboard = func(text string) error {
		return expectedErr
	}
	timerScheduled := false
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		timerScheduled = true
		tm := time.NewTimer(time.Hour)
		tm.Stop()
		return tm
	}
	clipboardOS = "darwin"
	writeConcealedClipboard = func(string, []string) error { return expectedErr }

	err := copyPasswordToClipboard("secret123")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}
	if !strings.Contains(err.Error(), "write password to clipboard:") {
		t.Fatalf("expected wrapped error context, got %v", err)
	}
	if timerScheduled {
		t.Fatal("expected expiration timer not to be scheduled on write error")
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

func TestCopyPasswordToClipboard_DefaultRetentionAndConcealedFlagsWorkflow(t *testing.T) {
	if DefaultClipboardClearTimeout != 10*time.Second {
		t.Fatalf("expected shortened default timeout of 10s, got %v", DefaultClipboardClearTimeout)
	}

	platforms := []struct {
		goos        string
		wantFlags   []string
		wantTimeout time.Duration
	}{
		{"darwin", []string{"org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"}, DefaultClipboardClearTimeout},
		{"linux", []string{"x-kde-passwordManagerHint=secret"}, DefaultClipboardClearTimeout},
		{"windows", []string{"ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory=false"}, DefaultClipboardClearTimeout},
		{"freebsd", nil, UnhintedClipboardClearTimeout},
	}

	for _, tc := range platforms {
		t.Run(tc.goos, func(t *testing.T) {
			resetClipboardTestState(t)

			var currentClipboard string
			writeClipboard = func(text string) error {
				currentClipboard = text
				return nil
			}
			readClipboard = func() (string, error) {
				return currentClipboard, nil
			}

			clipboardOS = tc.goos
			var appliedFlags []string
			writeConcealedClipboard = func(text string, flags []string) error {
				appliedFlags = append([]string(nil), flags...)
				currentClipboard = text
				return nil
			}

			var scheduledDuration time.Duration
			var scheduledFn func()
			afterFunc = func(d time.Duration, f func()) *time.Timer {
				scheduledDuration = d
				scheduledFn = f
				tm := time.NewTimer(time.Hour)
				tm.Stop()
				return tm
			}

			if err := copyPasswordToClipboard("top-secret"); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if currentClipboard != "top-secret" {
				t.Fatalf("expected clipboard to contain secret, got %q", currentClipboard)
			}
			if !reflect.DeepEqual(appliedFlags, tc.wantFlags) {
				t.Fatalf("expected concealed flags %v, got %v", tc.wantFlags, appliedFlags)
			}
			if scheduledDuration != tc.wantTimeout {
				t.Fatalf("expected scheduled timeout %v, got %v", tc.wantTimeout, scheduledDuration)
			}

			scheduledFn()
			if currentClipboard != "" {
				t.Fatalf("expected secret to be cleared promptly on timeout, got %q", currentClipboard)
			}
		})
	}
}

func TestConcealedClipboardFlags_PlatformEvaluation(t *testing.T) {
	tests := []struct {
		name string
		goos string
		want []string
	}{
		{
			name: "darwin",
			goos: "darwin",
			want: []string{"org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"},
		},
		{
			name: "linux",
			goos: "linux",
			want: []string{"x-kde-passwordManagerHint=secret"},
		},
		{
			name: "windows",
			goos: "windows",
			want: []string{"ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory=false"},
		},
		{
			name: "unsupported_os",
			goos: "plan9",
			want: nil,
		},
		{
			name: "empty_os",
			goos: "",
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ConcealedClipboardFlags(tc.goos)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ConcealedClipboardFlags(%q) = %v, want %v", tc.goos, got, tc.want)
			}
		})
	}
}

func TestCopyPasswordToClipboard_UnhintedPlatformsUseShorterRetention(t *testing.T) {
	if UnhintedClipboardClearTimeout >= DefaultClipboardClearTimeout {
		t.Fatalf("expected unhinted timeout %v below default %v", UnhintedClipboardClearTimeout, DefaultClipboardClearTimeout)
	}
	tests := []struct {
		goos       string
		configured time.Duration
		want       time.Duration
	}{
		{goos: "plan9", configured: DefaultClipboardClearTimeout, want: UnhintedClipboardClearTimeout},
		{goos: "openbsd", configured: time.Minute, want: UnhintedClipboardClearTimeout},
		{goos: "", configured: DefaultClipboardClearTimeout, want: UnhintedClipboardClearTimeout},
		{goos: "netbsd", configured: 2 * time.Second, want: 2 * time.Second},
		{goos: "linux", configured: 15 * time.Second, want: 15 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.goos+"/"+tc.configured.String(), func(t *testing.T) {
			resetClipboardTestState(t)
			writeClipboard = func(string) error { return nil }
			clipboardOS, writeConcealedClipboard = tc.goos, forwardConcealedWrite
			clipboardClearTimeout = tc.configured
			var got time.Duration
			afterFunc = func(d time.Duration, f func()) *time.Timer {
				got = d
				tm := time.NewTimer(time.Hour)
				tm.Stop()
				return tm
			}
			if err := copyPasswordToClipboard("secret123"); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("goos %q: expected scheduled timeout %v, got %v", tc.goos, tc.want, got)
			}
		})
	}
}

func TestCopyPasswordToClipboard_PreservesChangedClipboardOnTimeout(t *testing.T) {
	resetClipboardTestState(t)

	var currentClipboard string
	writeClipboard = func(text string) error {
		currentClipboard = text
		return nil
	}
	readClipboard = func() (string, error) {
		return currentClipboard, nil
	}

	var scheduledFn func()
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		scheduledFn = f
		tm := time.NewTimer(time.Hour)
		tm.Stop()
		return tm
	}

	if err := copyPasswordToClipboard("secret123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Simulate user copying something else before expiration
	currentClipboard = "other-content"
	scheduledFn()

	if currentClipboard != "other-content" {
		t.Fatalf("expected modified clipboard content to be preserved, got %q", currentClipboard)
	}
}

// readFailureHarness fakes a clipboard whose first failReads reads fail and
// records scheduled callbacks and reported errors.
type readFailureHarness struct {
	clipboard string
	failReads int
	reads     int
	delays    []time.Duration
	callbacks []func()
	reported  []error
}

func newReadFailureHarness(t *testing.T, failReads int) *readFailureHarness {
	t.Helper()
	resetClipboardTestState(t)
	h := &readFailureHarness{failReads: failReads}
	writeClipboard = func(text string) error { h.clipboard = text; return nil }
	readClipboard = func() (string, error) {
		h.reads++
		if h.reads <= h.failReads {
			return "", errReadFailure
		}
		return h.clipboard, nil
	}
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		h.delays = append(h.delays, d)
		h.callbacks = append(h.callbacks, f)
		tm := time.NewTimer(time.Hour)
		tm.Stop()
		return tm
	}
	reportClipboardClearFailure = func(err error) { h.reported = append(h.reported, err) }
	if err := copyPasswordToClipboard("secret123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return h
}

var errReadFailure = errors.New("read failure")

func TestCopyPasswordToClipboard_ReadErrorOnTimeoutRetriesAndClears(t *testing.T) {
	h := newReadFailureHarness(t, 1)

	h.callbacks[0]()
	if h.clipboard != "secret123" {
		t.Fatalf("expected no clear before retry, got %q", h.clipboard)
	}
	if len(h.callbacks) != 2 || h.delays[1] != clipboardClearRetryDelays[0] {
		t.Fatalf("expected a retry scheduled after %v, got delays %v", clipboardClearRetryDelays[0], h.delays)
	}
	if len(h.reported) != 1 || !errors.Is(h.reported[0], errReadFailure) {
		t.Fatalf("expected read failure to be reported, got %v", h.reported)
	}

	h.callbacks[1]()
	if h.clipboard != "" {
		t.Fatalf("expected retry to clear clipboard, got %q", h.clipboard)
	}
	if h.reads != 2 {
		t.Fatalf("expected 2 reads, got %d", h.reads)
	}
}

func TestCopyPasswordToClipboard_PersistentReadErrorForcesClear(t *testing.T) {
	h := newReadFailureHarness(t, 1000)
	for i := 0; i < len(h.callbacks); i++ {
		h.callbacks[i]()
	}
	if want := len(clipboardClearRetryDelays) + 1; h.reads != want {
		t.Fatalf("expected %d bounded read attempts, got %d", want, h.reads)
	}
	if h.clipboard != "" {
		t.Fatalf("expected unverified clipboard to be force-cleared, got %q", h.clipboard)
	}
	last := h.reported[len(h.reported)-1]
	if !errors.Is(last, errReadFailure) || !strings.Contains(last.Error(), "giving up") {
		t.Fatalf("expected final failure report, got %v", last)
	}
}

func TestCopyPasswordToClipboard_RetryAfterNewCopyDoesNothing(t *testing.T) {
	h := newReadFailureHarness(t, 1)
	h.callbacks[0]()

	if err := copyPasswordToClipboard("other-secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h.callbacks[1]()
	if h.clipboard != "other-secret" || h.reads != 1 {
		t.Fatalf("expected stale retry to skip, clipboard %q reads %d", h.clipboard, h.reads)
	}
}

func TestCopyPasswordToClipboard_NonPositiveTimeoutUsesDefaultAndWarns(t *testing.T) {
	for _, timeout := range []time.Duration{0, -5 * time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			resetClipboardTestState(t)

			var currentClipboard string
			writeClipboard = func(text string) error {
				currentClipboard = text
				return nil
			}
			readClipboard = func() (string, error) { return currentClipboard, nil }
			var warnings []error
			reportClipboardClearFailure = func(err error) { warnings = append(warnings, err) }
			clipboardClearTimeout = timeout
			clipboardOS = "linux"

			var appliedFlags []string
			writeConcealedClipboard = func(text string, flags []string) error {
				appliedFlags = append([]string(nil), flags...)
				return writeClipboard(text)
			}

			var scheduledFn func()
			var scheduled time.Duration
			afterFunc = func(d time.Duration, f func()) *time.Timer {
				scheduled, scheduledFn = d, f
				tm := time.NewTimer(time.Hour)
				tm.Stop()
				return tm
			}

			if err := copyPasswordToClipboard("secret123"); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if currentClipboard != "secret123" {
				t.Fatalf("expected clipboard to contain secret, got %q", currentClipboard)
			}
			wantFlags := []string{"x-kde-passwordManagerHint=secret"}
			if !reflect.DeepEqual(appliedFlags, wantFlags) {
				t.Fatalf("expected concealed flags %v, got %v", wantFlags, appliedFlags)
			}
			if scheduledFn == nil || scheduled != DefaultClipboardClearTimeout {
				t.Fatalf("expected default timeout %v scheduled for %v, got %v", DefaultClipboardClearTimeout, timeout, scheduled)
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0].Error(), "invalid clipboard clear timeout") {
				t.Fatalf("expected a warning about the invalid timeout, got %v", warnings)
			}
			scheduledFn()
			if currentClipboard != "" {
				t.Fatalf("expected secret cleared at default expiry, got %q", currentClipboard)
			}
		})
	}
}
