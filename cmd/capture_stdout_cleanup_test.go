package cmd

import (
	"fmt"
	"os"
	"testing"
)

// Count descriptors only in the isolated child, where unrelated tests cannot
// open files concurrently. ReadDir's own descriptor is closed before returning.
func removeCaptureDescriptorCount(t *testing.T) int {
	t.Helper()
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err == nil {
			return len(entries)
		}
	}
	t.Skip("descriptor enumeration is unavailable")
	return 0
}

func TestCaptureRemoveStdoutFatalChild(t *testing.T) {
	if os.Getenv("PWD_MANAGER_CAPTURE_FATAL_CHILD") != "1" {
		return
	}
	original := os.Stdout
	before := removeCaptureDescriptorCount(t)
	var writer *os.File
	// Registered first so this runs after the capture's reader cleanup.
	t.Cleanup(func() {
		if os.Stdout != original {
			t.Error("stdout was not restored after Fatal")
			return
		}
		if writer == nil {
			t.Error("callback did not run")
			return
		}
		if _, err := writer.Stat(); err == nil {
			t.Error("capture writer remains open after Fatal")
			return
		}
		if after := removeCaptureDescriptorCount(t); after != before {
			t.Errorf("descriptor count after Fatal = %d, before = %d", after, before)
			return
		}
		fmt.Println("capture fatal cleanup verified")
	})
	captureRemoveStdout(t, func() {
		writer = os.Stdout
		t.Fatal("intentional fatal inside capture")
	})
}

func TestCaptureRemoveStdoutEmpty(t *testing.T) {
	original := os.Stdout
	var writer *os.File
	out := captureRemoveStdout(t, func() { writer = os.Stdout })
	if out != "" {
		t.Fatalf("empty callback captured %q", out)
	}
	if os.Stdout != original {
		t.Error("stdout was not restored")
	}
	if _, err := writer.Stat(); err == nil {
		t.Error("capture writer remains open after normal return")
	}
}
