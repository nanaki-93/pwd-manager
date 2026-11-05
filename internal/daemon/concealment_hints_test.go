package daemon

import (
	"errors"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// Without an installed hint applier no concealment hint reaches the
// clipboard, so even platforms with known hints must use the unhinted cap.
func TestCopyPasswordToClipboard_NoHintApplierUsesUnhintedRetention(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			resetClipboardTestState(t)
			writeConcealedClipboard = nil
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

func TestCopyPasswordToClipboard_ConcealmentFailureNeverFallsBackToPlaintext(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			resetClipboardTestState(t)
			clipboardOS = goos
			failure := errors.New("native concealment unavailable")
			calls := 0
			writeConcealedClipboard = func(string, []string) error {
				calls++
				return failure
			}
			writeClipboard = func(text string) error {
				if text != "" {
					t.Fatal("concealment failure must not publish plaintext")
				}
				return nil
			}
			readClipboard = func() (string, error) { return "", nil }
			afterFunc = func(time.Duration, func()) *time.Timer {
				t.Fatal("failed concealed write must not schedule expiration")
				return nil
			}
			if err := copyPasswordToClipboard("dummy-secret"); !errors.Is(err, failure) {
				t.Fatalf("expected native failure to propagate, got %v", err)
			}
			if calls != 1 {
				t.Fatalf("expected exactly one concealed write, got %d", calls)
			}
		})
	}
}

// forwardConcealedWrite is a fake native writer that drops the hints and
// stores the text through the test's writeClipboard fake.
func forwardConcealedWrite(text string, _ []string) error {
	return writeClipboard(text)
}

// Regression: no native writer existed, so hints were never attached on any
// OS. Platforms with native clipboard APIs must install one by default.
func TestNativeConcealedClipboardWriter_InstalledOnHintedPlatforms(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("no native concealed writer on %s", runtime.GOOS)
	}
	if nativeConcealedClipboardWriter() == nil {
		t.Fatalf("expected a native concealed clipboard writer on %s", runtime.GOOS)
	}
}

// The password and its hints must reach the clipboard in one write: the plain
// writer must not publish the secret unhinted first.
func TestCopyPasswordToClipboard_WritesPasswordAndHintsTogether(t *testing.T) {
	resetClipboardTestState(t)
	clipboardOS = "darwin"
	writeClipboard = func(string) error {
		t.Fatal("password must not be written without concealment hints")
		return nil
	}
	var gotText string
	var gotFlags []string
	writeConcealedClipboard = func(text string, flags []string) error {
		gotText, gotFlags = text, flags
		return nil
	}
	afterFunc = func(time.Duration, func()) *time.Timer {
		tm := time.NewTimer(time.Hour)
		tm.Stop()
		return tm
	}
	if err := copyPasswordToClipboard("secret123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotText != "secret123" || !reflect.DeepEqual(gotFlags, ConcealedClipboardFlags("darwin")) {
		t.Fatalf("expected secret with darwin flags in one write, got %q %v", gotText, gotFlags)
	}
}
