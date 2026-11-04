package daemon

import (
	"testing"
	"time"
)

// Without an installed hint applier no concealment hint reaches the
// clipboard, so even platforms with known hints must use the unhinted cap.
func TestCopyPasswordToClipboard_NoHintApplierUsesUnhintedRetention(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			resetClipboardTestState(t)
			markClipboardConcealed = nil
			writeClipboard = func(string) error { return nil }
			clipboardOS = goos
			clipboardClearTimeout = DefaultClipboardClearTimeout
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
			if got != UnhintedClipboardClearTimeout {
				t.Fatalf("expected unhinted timeout %v without hint applier, got %v", UnhintedClipboardClearTimeout, got)
			}
		})
	}
}

func TestMarkClipboardConcealed_DefaultAppliesNoHints(t *testing.T) {
	if markClipboardConcealed != nil {
		t.Fatal("default markClipboardConcealed must be nil: writeClipboard cannot attach hints")
	}
}
