package cmd

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
)

// addClipboardClearDelay is how long a password copied by `add --copy` stays
// on the clipboard before it is cleared.
const addClipboardClearDelay = 10 * time.Second

// Bounds on how long a copied password may stay on the clipboard. Delays
// outside them (negative, or huge values from a misconfigured or tampered
// config) are clamped so the password is always cleared promptly: a
// non-positive delay clears it at once, a huge one after at most the max.
const (
	minClipboardClearDelay = 0
	maxClipboardClearDelay = 5 * time.Minute
)

// clampClipboardClearDelay limits delay to
// [minClipboardClearDelay, maxClipboardClearDelay].
func clampClipboardClearDelay(delay time.Duration) time.Duration {
	if delay < minClipboardClearDelay {
		return minClipboardClearDelay
	}
	if delay > maxClipboardClearDelay {
		return maxClipboardClearDelay
	}
	return delay
}

var (
	// clipboardClearWaiter waits for delay or ctx cancellation; a package
	// variable so tests can observe the delay without blocking.
	clipboardClearWaiter = waitClipboardClear
	// signalNotifyContext is signal.NotifyContext; a package variable so
	// tests can observe when signal capture ends.
	signalNotifyContext = signal.NotifyContext

	clipboardReadAll = clipboard.ReadAll
	// clipboardClearer waits, then clears pwd from the clipboard; a package
	// variable so tests never block or touch the real clipboard.
	clipboardClearer = clearCopiedPasswordOnExit
	// getClipboardClearer is the `get --copy` counterpart of clipboardClearer,
	// taking the user-configured delay.
	getClipboardClearer = clearCopiedPasswordAfter
)

// clearCopiedPasswordOnExit keeps the CLI alive for addClipboardClearDelay,
// or until a terminating signal, and then clears pwd from the clipboard. The process
// exits right after `add`, so a background timer would never fire.
func clearCopiedPasswordOnExit(pwd string) error {
	return clearCopiedPasswordAfter(pwd, addClipboardClearDelay)
}

// clearCopiedPasswordAfter tells the user (on stderr) how long pwd stays on
// the clipboard, keeps the CLI alive for delay or until a terminating signal
// (SIGINT, SIGTERM, SIGHUP when the terminal closes, SIGQUIT), and then
// clears pwd from the clipboard if it still holds it. delay is clamped to
// [minClipboardClearDelay, maxClipboardClearDelay]. Signal capture ends
// before the clipboard is touched, so a second signal during clipboard I/O
// gets the default handling and terminates the process.
func clearCopiedPasswordAfter(pwd string, delay time.Duration) error {
	delay = clampClipboardClearDelay(delay)
	ctx, stop := signalNotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer stop()
	fmt.Fprintf(os.Stderr, "Password copied to clipboard; it will be cleared in %v (press Ctrl+C to clear now).\n", delay)
	clipboardClearWaiter(ctx, delay)
	stop()
	return verifyAndClearClipboard(pwd)
}

// waitClipboardClear blocks until delay elapses or ctx is cancelled.
func waitClipboardClear(ctx context.Context, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// clearClipboardAfter waits for delay or ctx cancellation, then clears the
// clipboard if it still holds pwd (see verifyAndClearClipboard).
func clearClipboardAfter(ctx context.Context, pwd string, delay time.Duration) error {
	waitClipboardClear(ctx, delay)
	return verifyAndClearClipboard(pwd)
}

// verifyAndClearClipboard clears the clipboard if it still holds pwd. If the
// clipboard cannot be read, it is cleared without verification and the read
// failure is returned.
func verifyAndClearClipboard(pwd string) error {
	current, readErr := clipboardReadAll()
	if readErr == nil && subtle.ConstantTimeCompare([]byte(current), []byte(pwd)) != 1 {
		return nil // overwritten by the user since; leave it alone
	}
	if err := clipboardWriteAll(""); err != nil {
		return errors.Join(
			fmt.Errorf("clear password from clipboard: %w; the password may still be on the clipboard", err),
			readErr)
	}
	if readErr != nil {
		return fmt.Errorf("read clipboard before clearing password (cleared without verification): %w", readErr)
	}
	return nil
}
