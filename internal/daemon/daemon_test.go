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
	origWrite := writeClipboard
	origRead := readClipboard
	origAfter := afterFunc
	origTimeout := clipboardClearTimeout
	origOS := clipboardOS
	origMarkConcealed := markClipboardConcealed

	t.Cleanup(func() {
		clipboardMu.Lock()
		if clipboardTimer != nil {
			clipboardTimer.Stop()
			clipboardTimer = nil
		}
		clipboardToken = 0
		clipboardMu.Unlock()

		writeClipboard = origWrite
		readClipboard = origRead
		afterFunc = origAfter
		clipboardClearTimeout = origTimeout
		clipboardOS = origOS
		markClipboardConcealed = origMarkConcealed
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
	concealedMarked := false
	markClipboardConcealed = func(flags []string) {
		concealedMarked = true
	}

	err := copyPasswordToClipboard("secret123")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}
	if !strings.Contains(err.Error(), "write password to clipboard:") {
		t.Fatalf("expected wrapped error context, got %v", err)
	}
	if concealedMarked {
		t.Fatal("expected concealed clipboard flags not to be marked on write error")
	}
	if timerScheduled {
		t.Fatal("expected expiration timer not to be scheduled on write error")
	}
}

func TestCopyPasswordToClipboard_ClearsMatchingSecretAfterTimeout(t *testing.T) {
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
	var scheduledDuration time.Duration
	clipboardClearTimeout = 15 * time.Second
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		scheduledDuration = d
		scheduledFn = f
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
	if scheduledDuration != 15*time.Second {
		t.Fatalf("expected timeout 15s, got %v", scheduledDuration)
	}
	if scheduledFn == nil {
		t.Fatal("expected expiration callback to be scheduled")
	}

	scheduledFn()
	if currentClipboard != "" {
		t.Fatalf("expected clipboard to be cleared, got %q", currentClipboard)
	}
}

func TestCopyPasswordToClipboard_DefaultRetentionAndConcealedFlagsWorkflow(t *testing.T) {
	if DefaultClipboardClearTimeout != 10*time.Second {
		t.Fatalf("expected shortened default timeout of 10s, got %v", DefaultClipboardClearTimeout)
	}

	platforms := []struct {
		goos      string
		wantFlags []string
	}{
		{
			goos:      "darwin",
			wantFlags: []string{"org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"},
		},
		{
			goos:      "linux",
			wantFlags: []string{"x-kde-passwordManagerHint=secret"},
		},
		{
			goos:      "windows",
			wantFlags: []string{"ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory=false"},
		},
		{
			goos:      "freebsd",
			wantFlags: nil,
		},
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
			markCalled := false
			markClipboardConcealed = func(flags []string) {
				markCalled = true
				if flags != nil {
					appliedFlags = append([]string(nil), flags...)
				}
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
			if !markCalled {
				t.Fatal("expected markClipboardConcealed to be called")
			}
			if !reflect.DeepEqual(appliedFlags, tc.wantFlags) {
				t.Fatalf("expected concealed flags %v, got %v", tc.wantFlags, appliedFlags)
			}
			if scheduledDuration != DefaultClipboardClearTimeout {
				t.Fatalf("expected scheduled timeout %v, got %v", DefaultClipboardClearTimeout, scheduledDuration)
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

func TestCopyPasswordToClipboard_ReadErrorOnTimeoutDoesNotClear(t *testing.T) {
	resetClipboardTestState(t)

	writes := 0
	writeClipboard = func(text string) error {
		writes++
		return nil
	}
	readClipboard = func() (string, error) {
		return "", errors.New("read failure")
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
	if writes != 1 {
		t.Fatalf("expected 1 clipboard write, got %d", writes)
	}

	scheduledFn()
	if writes != 1 {
		t.Fatalf("expected no clear write when read fails, got %d total writes", writes)
	}
}

func TestCopyPasswordToClipboard_NonPositiveTimeoutSkipsTimer(t *testing.T) {
	for _, timeout := range []time.Duration{0, -5 * time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			resetClipboardTestState(t)

			var currentClipboard string
			writeClipboard = func(text string) error {
				currentClipboard = text
				return nil
			}
			clipboardClearTimeout = timeout
			clipboardOS = "linux"

			var appliedFlags []string
			markClipboardConcealed = func(flags []string) {
				appliedFlags = append([]string(nil), flags...)
			}

			timerScheduled := false
			afterFunc = func(d time.Duration, f func()) *time.Timer {
				timerScheduled = true
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
				t.Fatalf("expected concealed flags %v even when timeout is disabled, got %v", wantFlags, appliedFlags)
			}
			if timerScheduled {
				t.Fatalf("expected no timer scheduled for timeout %v", timeout)
			}
		})
	}
}

func TestCopyPasswordToClipboard_ReplacesExistingTimer(t *testing.T) {
	resetClipboardTestState(t)

	var currentClipboard string
	writeClipboard = func(text string) error {
		currentClipboard = text
		return nil
	}
	readClipboard = func() (string, error) {
		return currentClipboard, nil
	}

	var callbacks []func()
	var timers []*time.Timer
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		callbacks = append(callbacks, f)
		tm := time.NewTimer(time.Hour)
		timers = append(timers, tm)
		return tm
	}
	defer func() {
		for _, tm := range timers {
			tm.Stop()
		}
	}()

	if err := copyPasswordToClipboard("first-secret"); err != nil {
		t.Fatalf("unexpected error on first copy: %v", err)
	}
	if err := copyPasswordToClipboard("second-secret"); err != nil {
		t.Fatalf("unexpected error on second copy: %v", err)
	}

	if len(timers) != 2 {
		t.Fatalf("expected 2 timers to be created, got %d", len(timers))
	}
	// Timer.Stop() returns false if the timer has already been stopped.
	if timers[0].Stop() {
		t.Fatal("expected first timer to have been stopped when second password was copied")
	}

	// Running the second callback should clear the second secret.
	callbacks[1]()
	if currentClipboard != "" {
		t.Fatalf("expected second timer callback to clear clipboard, got %q", currentClipboard)
	}
}

func TestCopyPasswordToClipboard_StaleTimerDoesNotClearRecopiedSameSecret(t *testing.T) {
	resetClipboardTestState(t)

	var currentClipboard string
	writeClipboard = func(text string) error {
		currentClipboard = text
		return nil
	}
	readClipboard = func() (string, error) {
		return currentClipboard, nil
	}

	var callbacks []func()
	var timers []*time.Timer
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		callbacks = append(callbacks, f)
		tm := time.NewTimer(time.Hour)
		timers = append(timers, tm)
		return tm
	}
	defer func() {
		for _, tm := range timers {
			tm.Stop()
		}
	}()

	if err := copyPasswordToClipboard("same-secret"); err != nil {
		t.Fatalf("unexpected error on first copy: %v", err)
	}
	if err := copyPasswordToClipboard("same-secret"); err != nil {
		t.Fatalf("unexpected error on second copy: %v", err)
	}

	if len(callbacks) != 2 {
		t.Fatalf("expected 2 callbacks to be scheduled, got %d", len(callbacks))
	}

	// Simulate an already-fired first timer callback running after the second copy.
	callbacks[0]()
	if currentClipboard != "same-secret" {
		t.Fatalf("expected stale timer callback not to clear re-copied secret, got %q", currentClipboard)
	}

	// The active second timer callback should still clear the secret.
	callbacks[1]()
	if currentClipboard != "" {
		t.Fatalf("expected latest timer callback to clear clipboard, got %q", currentClipboard)
	}
}

func TestCopyPasswordToClipboard_StaleTimerInvalidatedWhenSubsequentCopyHasDisabledTimeout(t *testing.T) {
	resetClipboardTestState(t)

	var currentClipboard string
	writeClipboard = func(text string) error {
		currentClipboard = text
		return nil
	}
	readClipboard = func() (string, error) {
		return currentClipboard, nil
	}

	var callbacks []func()
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		callbacks = append(callbacks, f)
		tm := time.NewTimer(time.Hour)
		tm.Stop()
		return tm
	}

	if err := copyPasswordToClipboard("same-secret"); err != nil {
		t.Fatalf("unexpected error on first copy: %v", err)
	}
	if len(callbacks) != 1 {
		t.Fatalf("expected 1 callback scheduled, got %d", len(callbacks))
	}

	// Disable timeout for the second copy of the same password.
	clipboardClearTimeout = 0
	if err := copyPasswordToClipboard("same-secret"); err != nil {
		t.Fatalf("unexpected error on second copy: %v", err)
	}

	// Even if the first timer had already fired and now acquires the lock, it must not clear.
	callbacks[0]()
	if currentClipboard != "same-secret" {
		t.Fatalf("expected stale timer callback not to clear secret after timeout-disabled copy, got %q", currentClipboard)
	}
}

func TestCopyPasswordToClipboard_StaleTimerInvalidatedOnSubsequentWriteError(t *testing.T) {
	resetClipboardTestState(t)

	var currentClipboard string
	failWrite := false
	writeClipboard = func(text string) error {
		if failWrite {
			return errors.New("write failed")
		}
		currentClipboard = text
		return nil
	}
	readReads := 0
	readClipboard = func() (string, error) {
		readReads++
		return currentClipboard, nil
	}

	var scheduledFn func()
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		scheduledFn = f
		tm := time.NewTimer(time.Hour)
		tm.Stop()
		return tm
	}

	if err := copyPasswordToClipboard("same-secret"); err != nil {
		t.Fatalf("unexpected error on first copy: %v", err)
	}

	failWrite = true
	if err := copyPasswordToClipboard("same-secret"); err == nil {
		t.Fatal("expected write error on second copy")
	}

	scheduledFn()
	if readReads != 0 {
		t.Fatalf("expected stale callback to return before reading clipboard, got %d reads", readReads)
	}
}
