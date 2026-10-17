package daemon

import (
	"errors"
	"testing"
	"time"
)

func resetClipboardTestState(t *testing.T) {
	t.Helper()
	origWrite := writeClipboard
	origRead := readClipboard
	origAfter := afterFunc
	origTimeout := clipboardClearTimeout

	t.Cleanup(func() {
		clipboardMu.Lock()
		if clipboardTimer != nil {
			clipboardTimer.Stop()
			clipboardTimer = nil
		}
		clipboardMu.Unlock()

		writeClipboard = origWrite
		readClipboard = origRead
		afterFunc = origAfter
		clipboardClearTimeout = origTimeout
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

	err := copyPasswordToClipboard("secret123")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
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
