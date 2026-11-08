package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.design/x/hotkey"
)

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

	// A non-positive timeout on the second copy falls back to the default.
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
		if scheduledFn == nil { // keep the stale first-copy timer, not the clear retry
			scheduledFn = f
		}
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
	if readReads != 1 { // only the failed copy's verification before its best-effort clear
		t.Fatalf("expected stale callback to return before reading clipboard, got %d reads", readReads)
	}
}

type concurrentClipboardHarness struct {
	mu               sync.Mutex
	currentClipboard string
	markCount        int
	clearWrites      int
	callbacks        []func()
}

func newConcurrentClipboardHarness() *concurrentClipboardHarness {
	h := &concurrentClipboardHarness{}
	clipboardOS, writeClipboard = "windows", h.write
	readClipboard = h.read
	writeConcealedClipboard = func(text string, _ []string) error {
		h.mu.Lock()
		h.markCount++
		h.mu.Unlock()
		return writeClipboard(text)
	}
	afterFunc = func(d time.Duration, f func()) *time.Timer {
		h.mu.Lock()
		h.callbacks = append(h.callbacks, f)
		h.mu.Unlock()
		tm := time.NewTimer(time.Hour)
		tm.Stop()
		return tm
	}
	return h
}

func (h *concurrentClipboardHarness) write(text string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if text == "" {
		h.clearWrites++
	}
	h.currentClipboard = text
	return nil
}

func (h *concurrentClipboardHarness) read() (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.currentClipboard, nil
}

const nonBlockingCopyGuard = 5 * time.Second // bounds a hung copy, not latency

// copyCompletesWhileBlocked requires a concurrent copy to finish before guard
// fires; on timeout it calls release and waits for the copy, then errors.
func copyCompletesWhileBlocked(pwd string, guard time.Duration, release func()) error {
	done := make(chan error, 1)
	go func() { done <- copyPasswordToClipboard(pwd) }()
	select {
	case err := <-done:
		return err
	case <-time.After(guard):
		release()
		<-done
		return fmt.Errorf("concurrent copy still blocked after %v: slow clipboard I/O holds clipboardMu", guard)
	}
}

func assertFastCopyPassword(t *testing.T, pwd string, release func()) {
	t.Helper()
	if err := copyCompletesWhileBlocked(pwd, nonBlockingCopyGuard, release); err != nil {
		t.Fatalf("expected concurrent copy to finish while slow clipboard I/O is blocked: %v", err)
	}
}

func TestCopyCompletesWhileBlocked_FailsWhenLockHeld(t *testing.T) {
	resetClipboardTestState(t)
	newConcurrentClipboardHarness()
	clipboardMu.Lock()
	err := copyCompletesWhileBlocked("held-secret", 20*time.Millisecond, clipboardMu.Unlock)
	if err == nil || !strings.Contains(err.Error(), "still blocked") {
		t.Fatalf("expected blocked copy to be reported, got %v", err)
	}
}

func TestCopyPasswordToClipboard_SlowWriteDoesNotHoldLockAndCancelsStaleCopy(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()

	slowWriteStarted := make(chan struct{})
	releaseSlowWrite := make(chan struct{})
	writeClipboard = func(text string) error {
		if text == "slow-secret" {
			close(slowWriteStarted)
			<-releaseSlowWrite
			return nil
		}
		return h.write(text)
	}

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- copyPasswordToClipboard("slow-secret")
	}()
	<-slowWriteStarted

	release := sync.OnceFunc(func() { close(releaseSlowWrite) })
	t.Cleanup(release)
	assertFastCopyPassword(t, "fast-secret", release)

	release()
	if err := <-firstDone; err != nil {
		t.Fatalf("unexpected error from first copy: %v", err)
	}

	h.mu.Lock()
	gotMarks := h.markCount
	gotCallbacks := len(h.callbacks)
	activeCallback := h.callbacks[0]
	h.mu.Unlock()

	if gotMarks != 2 {
		t.Fatalf("expected both password writes to carry concealment hints, got %d", gotMarks)
	}
	if gotCallbacks != 1 {
		t.Fatalf("expected only 1 timer scheduled (stale copy cancelled), got %d", gotCallbacks)
	}

	activeCallback()
	if got, _ := h.read(); got != "" {
		t.Fatalf("expected active timer to clear fast-secret, got %q", got)
	}
}

func TestCopyPasswordToClipboard_SlowReadOnExpirationDoesNotBlockConcurrentCopyAndSkipsClear(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()

	slowReadStarted := make(chan struct{})
	releaseSlowRead := make(chan struct{})
	readClipboard = func() (string, error) {
		close(slowReadStarted)
		<-releaseSlowRead
		return "first-secret", nil
	}

	if err := copyPasswordToClipboard("first-secret"); err != nil {
		t.Fatalf("unexpected error on first copy: %v", err)
	}

	expireDone := make(chan struct{})
	go func() {
		h.callbacks[0]()
		close(expireDone)
	}()
	<-slowReadStarted

	release := sync.OnceFunc(func() { close(releaseSlowRead) })
	t.Cleanup(release)
	assertFastCopyPassword(t, "second-secret", release)

	release()
	<-expireDone

	h.mu.Lock()
	gotClearWrites := h.clearWrites
	gotClipboard := h.currentClipboard
	h.mu.Unlock()

	if gotClearWrites != 0 {
		t.Fatalf("expected stale expiration not to clear clipboard after new copy, got %d clear writes", gotClearWrites)
	}
	if gotClipboard != "second-secret" {
		t.Fatalf("expected second-secret to remain in clipboard, got %q", gotClipboard)
	}
}

// A failed copy cancels the earlier password's pending clear, so it must
// clear that password itself instead of leaving it on the clipboard.
func TestFailedCopyStillClearsPreviousPassword(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	writeErr := errors.New("clipboard unavailable")
	writeClipboard = func(text string) error {
		if text != "" {
			return writeErr
		}
		return h.write(text)
	}
	err := copyPasswordToClipboard("new-secret")
	if !errors.Is(err, writeErr) || !strings.Contains(err.Error(), "write password to clipboard") {
		t.Fatalf("expected wrapped write error, got %v", err)
	}
	if got, _ := h.read(); got != "" {
		t.Fatalf("expected previous password to be cleared, got %q", got)
	}
}

func TestCopyPasswordToClipboard_FailedWriteReportsFailedClear(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	writeErr := errors.New("clipboard unavailable")
	clearErr := errors.New("clear refused")
	writeClipboard = func(text string) error {
		if text == "" {
			return clearErr
		}
		return writeErr
	}
	err := copyPasswordToClipboard("new-secret")
	if !errors.Is(err, writeErr) || !errors.Is(err, clearErr) {
		t.Fatalf("expected write and clear errors, got %v", err)
	}
	if !strings.Contains(err.Error(), "write password to clipboard") {
		t.Fatalf("expected write context, got %v", err)
	}
	if got, _ := h.read(); got != "old-secret" {
		t.Fatalf("precondition: expected old password to remain, got %q", got)
	}
}

// The best-effort clear after a failed copy must verify the clipboard first,
// so content the user copied meanwhile is not erased.
func TestFailedCopyDoesNotEraseUnrelatedContent(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	if err := copyPasswordToClipboard("old-secret"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = h.write("user-content")
	writeClipboard = func(text string) error {
		if text != "" {
			return errors.New("clipboard unavailable")
		}
		return h.write(text)
	}
	if err := copyPasswordToClipboard("new-secret"); err == nil {
		t.Fatal("expected write error")
	}
	if got, _ := h.read(); got != "user-content" {
		t.Fatalf("unrelated content erased: got %q", got)
	}
}

// An earlier copy whose write lands only after a later copy failed (before
// any timer was scheduled) must still get a clear.
func TestFailedCopyDuringInFlightCopyStillClearsIt(t *testing.T) {
	resetClipboardTestState(t)
	h := newConcurrentClipboardHarness()
	started, release := make(chan struct{}), make(chan struct{})
	writeErr := errors.New("clipboard unavailable")
	writeClipboard = func(text string) error {
		switch text {
		case "old-secret":
			close(started)
			<-release
		case "new-secret":
			return writeErr
		}
		return h.write(text)
	}
	var releaseOnce sync.Once
	releaseOld := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseOld()
	oldDone := make(chan error, 1)
	go func() { oldDone <- copyPasswordToClipboard("old-secret") }()
	<-started
	newDone := make(chan error, 1)
	go func() { newDone <- copyPasswordToClipboard("new-secret") }()
	select {
	case err := <-newDone:
		if !errors.Is(err, writeErr) {
			t.Fatalf("expected write error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second copy blocked waiting for the in-flight copy; it must fail without waiting")
	}
	releaseOld()
	if err := <-oldDone; err != nil {
		t.Fatalf("unexpected error from older copy: %v", err)
	}
	h.mu.Lock()
	callbacks := append([]func(){}, h.callbacks...)
	h.mu.Unlock()
	if len(callbacks) != 1 {
		t.Fatalf("expected one clear scheduled for the late write, got %d", len(callbacks))
	}
	callbacks[0]()
	if got, _ := h.read(); got != "" {
		t.Fatalf("expected late-landing password cleared, got %q", got)
	}
}

func TestServeHotkeyCancelVerifiesTrackedPasswordsAndStopsTimer(t *testing.T) {
	for _, tc := range []struct {
		name, current, want string
		wantWrites          int
	}{
		{"active password", "active-secret", "", 1},
		{"stale password", "older-secret", "", 1},
		{"unrelated clipboard", "user text", "user text", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetClipboardTestState(t)
			clip, writes, reads := "", 0, 0
			writeClipboard = func(s string) error {
				clip = s
				writes++
				return nil
			}
			readClipboard = func() (string, error) {
				reads++
				return clip, nil
			}
			var pending *time.Timer
			var callback func()
			afterFunc = func(_ time.Duration, f func()) *time.Timer {
				callback = f
				pending = time.NewTimer(time.Hour)
				return pending
			}
			for _, pwd := range []string{"older-secret", "active-secret"} {
				if err := copyPasswordToClipboard(pwd); err != nil {
					t.Fatalf("copy: %v", err)
				}
			}
			// Simulate an older write landing last, or an external clipboard edit.
			clip, writes = tc.current, 0
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := serveHotkey(ctx, make(chan hotkey.Event), func() {}); err != nil {
				t.Fatalf("serveHotkey: %v", err)
			}
			if clip != tc.want || writes != tc.wantWrites || reads != 1 {
				t.Fatalf("shutdown: clipboard=%q writes=%d reads=%d; want %q, %d, 1", clip, writes, reads, tc.want, tc.wantWrites)
			}
			if pending.Stop() {
				t.Error("pending timer was not stopped on cancellation")
			}
			// Even a callback already dispatched before Stop must be invalidated.
			clip = "active-secret"
			callback()
			if clip != "active-secret" || writes != tc.wantWrites || reads != 1 {
				t.Fatal("cancelled callback accessed or cleared the clipboard again")
			}
		})
	}
}
