//go:build unix

package cmd

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestClearCopiedPasswordAfterFirstTerminatingSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT} {
		t.Run(sig.String(), func(t *testing.T) {
			oldWait, oldNotify := clipboardClearWaiter, signalNotifyContext
			t.Cleanup(func() { clipboardClearWaiter, signalNotifyContext = oldWait, oldNotify })
			stopped := false
			signalNotifyContext = func(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
				ctx, stop := oldNotify(parent, signals...)
				return ctx, func() { stop(); stopped = true }
			}
			clipboardClearWaiter = func(ctx context.Context, delay time.Duration) {
				if err := syscall.Kill(os.Getpid(), sig); err != nil {
					t.Fatalf("send signal: %v", err)
				}
				bounded, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				waitClipboardClear(bounded, delay)
				if ctx.Err() != context.Canceled {
					t.Fatal("first terminating signal did not cancel the wait")
				}
			}
			oldRead, oldWrite := clipboardReadAll, clipboardWriteAll
			t.Cleanup(func() { clipboardReadAll, clipboardWriteAll = oldRead, oldWrite })
			reads, writes := 0, 0
			clipboardReadAll = func() (string, error) {
				if !stopped {
					t.Fatal("signal capture active at clipboard read")
				}
				reads++
				return "test-secret", nil
			}
			clipboardWriteAll = func(value string) error {
				if value != "" || !stopped {
					t.Fatalf("unexpected write %q with stopped=%v", value, stopped)
				}
				writes++
				return nil
			}
			if err := clearCopiedPasswordAfter("test-secret", time.Minute); err != nil {
				t.Fatal(err)
			}
			if reads != 1 || writes != 1 {
				t.Fatalf("read/write counts = %d/%d, want 1/1", reads, writes)
			}
		})
	}
}

func TestClearCopiedPasswordAfterErrorContext(t *testing.T) {
	readErr, writeErr := errors.New("read failure"), errors.New("write failure")
	for _, tc := range []struct {
		name        string
		read, write error
		want        string
	}{
		{"read", readErr, nil, "read clipboard before clearing password (cleared without verification): read failure"},
		{"write", nil, writeErr, "clear password from clipboard: write failure; the password may still be on the clipboard"},
		{"both", readErr, writeErr, "clear password from clipboard: write failure; the password may still be on the clipboard\nread failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := fakeClipboard(t, tc.read, tc.write)
			*content = "test-secret"
			err := clearCopiedPasswordAfter("test-secret", time.Nanosecond)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			for _, cause := range []error{tc.read, tc.write} {
				if cause != nil && !errors.Is(err, cause) {
					t.Fatalf("lost wrapped cause %v: %v", cause, err)
				}
			}
			if strings.Contains(err.Error(), "test-secret") {
				t.Fatal("error exposed password")
			}
			if tc.write == nil && *content != "" {
				t.Fatal("read failure did not trigger fallback clear")
			}
		})
	}
}
