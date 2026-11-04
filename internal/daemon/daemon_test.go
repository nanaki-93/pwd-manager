package daemon

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
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
	origMarkConcealed := markClipboardConcealed
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
		markClipboardConcealed = origMarkConcealed
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
	clipboardOS, markClipboardConcealed = "linux", func([]string) {}
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
		{goos: "linux", configured: time.Minute, want: time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.goos+"/"+tc.configured.String(), func(t *testing.T) {
			resetClipboardTestState(t)
			writeClipboard = func(string) error { return nil }
			clipboardOS, markClipboardConcealed = tc.goos, func([]string) {}
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
			markClipboardConcealed = func(flags []string) {
				appliedFlags = append([]string(nil), flags...)
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
	writeClipboard = h.write
	readClipboard = h.read
	markClipboardConcealed = func(flags []string) {
		h.mu.Lock()
		h.markCount++
		h.mu.Unlock()
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

	if gotMarks != 1 {
		t.Fatalf("expected markClipboardConcealed only for active token, got %d calls", gotMarks)
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
