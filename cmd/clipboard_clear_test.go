//go:build unix

package cmd

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestClearCopiedPasswordAfterClearsOnSIGHUP closes the terminal (SIGHUP)
// while the CLI waits and expects the copied password to be cleared at once.
func TestClearCopiedPasswordAfterClearsOnSIGHUP(t *testing.T) {
	// Keep SIGHUP from killing the test binary if the code under test does
	// not trap it (the regression this test guards against).
	guard := make(chan os.Signal, 16)
	signal.Notify(guard, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(guard) })

	var mu sync.Mutex
	content, writes := "s3cr3t", []string{}
	origRead, origWrite := clipboardReadAll, clipboardWriteAll
	t.Cleanup(func() { clipboardReadAll, clipboardWriteAll = origRead, origWrite })
	clipboardReadAll = func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		return content, nil
	}
	clipboardWriteAll = func(s string) error {
		mu.Lock()
		defer mu.Unlock()
		content, writes = s, append(writes, s)
		return nil
	}

	const delay = 3 * time.Second
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- clearCopiedPasswordAfter("s3cr3t", delay) }()

	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var err error
wait:
	for {
		select {
		case err = <-done:
			break wait
		case <-ticker.C:
			if killErr := syscall.Kill(os.Getpid(), syscall.SIGHUP); killErr != nil {
				t.Fatalf("send SIGHUP: %v", killErr)
			}
		}
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= delay {
		t.Fatalf("SIGHUP did not cancel the wait; returned after %v", elapsed)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(writes) != 1 || writes[0] != "" {
		t.Fatalf("expected clipboard cleared with one empty write, got %q", writes)
	}
}

// TestClearCopiedPasswordAfterClampsDelay checks that out-of-range delays
// are clamped to [minClipboardClearDelay, maxClipboardClearDelay] before
// the wait starts, so a huge configured delay cannot keep the password on
// the clipboard indefinitely.
func TestClearCopiedPasswordAfterClampsDelay(t *testing.T) {
	tests := []struct {
		name  string
		delay time.Duration
		want  time.Duration
	}{
		{"zero", 0, minClipboardClearDelay},
		{"negative", -time.Hour, minClipboardClearDelay},
		{"very large", time.Duration(1<<63 - 1), maxClipboardClearDelay},
		{"just above max", maxClipboardClearDelay + time.Nanosecond, maxClipboardClearDelay},
		{"in range", 30 * time.Second, 30 * time.Second},
		{"tiny", time.Nanosecond, time.Nanosecond},
	}
	orig := clipboardClearWaiter
	t.Cleanup(func() { clipboardClearWaiter = orig })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got time.Duration
			clipboardClearWaiter = func(_ context.Context, pwd string, delay time.Duration) error {
				if pwd != "s3cr3t" {
					t.Errorf("waiter got pwd %q", pwd)
				}
				got = delay
				return nil
			}
			if err := clearCopiedPasswordAfter("s3cr3t", tt.delay); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("delay %v: waited %v, want %v", tt.delay, got, tt.want)
			}
		})
	}
}
