package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.design/x/hotkey"
)

func TestServeHotkeyCancelVerifiesTrackedPasswordsAndStopsTimer(t *testing.T) {
	for _, tc := range []struct {
		name, current, want string
		wantWrites          int
	}{
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

func TestServeHotkeyClearsPendingClipboardOnCancel(t *testing.T) {
	var mu sync.Mutex
	clip := ""
	origW, origR, origA, origC, origOS := writeClipboard, readClipboard, afterFunc, writeConcealedClipboard, clipboardOS
	t.Cleanup(func() {
		clipboardMu.Lock()
		if clipboardTimer != nil {
			clipboardTimer.Stop()
		}
		clipboardTimer = nil
		clipboardOwned, clipboardActivePwd, clipboardStalePwds = false, "", nil
		clipboardMu.Unlock()
		writeClipboard, readClipboard, afterFunc, writeConcealedClipboard, clipboardOS = origW, origR, origA, origC, origOS
	})
	writeClipboard = func(s string) error {
		mu.Lock()
		defer mu.Unlock()
		clip = s
		return nil
	}
	readClipboard = func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		return clip, nil
	}
	writeConcealedClipboard = nil
	clipboardOS = "darwin"
	afterFunc = func(_ time.Duration, f func()) *time.Timer {
		return time.AfterFunc(time.Hour, f)
	}

	if err := copyPasswordToClipboard("s3cret"); err != nil {
		t.Fatalf("copy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := serveHotkey(ctx, make(chan hotkey.Event), func() {}); err != nil {
		t.Fatalf("serveHotkey: %v", err)
	}

	mu.Lock()
	got := clip
	mu.Unlock()
	if got != "" {
		t.Fatalf("clipboard after shutdown = %q, want empty", got)
	}
}
