package cmd

import (
	"os"
	"strings"
	"testing"
	"time"
)

func captureGetStderr(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	defer func() {
		os.Stderr = old
		if err := f.Close(); err != nil {
			t.Errorf("close stderr capture: %v", err)
		}
	}()
	os.Stderr = f
	fn()
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestGetRevealWarnsWithoutLeakingSecretToStderr(t *testing.T) {
	stubRevealEnv(t, true, false)
	var diagnostic string
	out := captureStdout(t, func() {
		diagnostic = captureGetStderr(t, func() {
			if err := handleGetOutput("account", map[string]string{"account": "test-secret"}, false); err != nil {
				t.Fatal(err)
			}
		})
	})
	if out != "account:test-secret" {
		t.Fatalf("unexpected reveal output %q", out)
	}
	if !strings.Contains(diagnostic, "Warning:") || !strings.Contains(diagnostic, "plaintext") {
		t.Fatalf("missing plaintext warning: %q", diagnostic)
	}
	if strings.Contains(diagnostic, "test-secret") {
		t.Fatalf("stderr must not contain the password: %q", diagnostic)
	}
}

func TestGetClipboardClearAnnouncesDelayAndActuallyExpires(t *testing.T) {
	content := fakeClipboard(t, nil, nil)
	*content = "test-secret"
	// An already-due timer exercises the timer branch without sleeps or signals.
	diagnostic := captureGetStderr(t, func() {
		if err := clearCopiedPasswordAfter("test-secret", time.Nanosecond); err != nil {
			t.Fatal(err)
		}
	})
	if *content != "" {
		t.Fatal("expired clipboard entry was not cleared")
	}
	if !strings.Contains(diagnostic, "1ns") || !strings.Contains(diagnostic, "cleared") {
		t.Fatalf("missing configured expiry diagnostic: %q", diagnostic)
	}
	if strings.Contains(diagnostic, "test-secret") {
		t.Fatalf("expiry diagnostic contains password: %q", diagnostic)
	}
}
