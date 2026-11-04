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

var (
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
// clears pwd from the clipboard if it still holds it.
func clearCopiedPasswordAfter(pwd string, delay time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer stop()
	fmt.Fprintf(os.Stderr, "Password copied to clipboard; it will be cleared in %v (press Ctrl+C to clear now).\n", delay)
	return clearClipboardAfter(ctx, pwd, delay)
}

// clearClipboardAfter waits for delay or ctx cancellation, then clears the
// clipboard if it still holds pwd. If the clipboard cannot be read, it is
// cleared without verification and the read failure is returned.
func clearClipboardAfter(ctx context.Context, pwd string, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
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
