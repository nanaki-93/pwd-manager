package cmd

import (
	"errors"
	"os"
	"testing"
)

// Exercise timeout recovery directly rather than waiting ten seconds or
// deliberately leaving a blocked capture running in the test process.
func TestAbandonBlockedCaptureRestoresBeforeJoin(t *testing.T) {
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stalled capture pipe: %v", err)
	}
	t.Cleanup(func() {
		os.Stdout = original
		if err := reader.Close(); err != nil {
			t.Errorf("close stalled capture reader: %v", err)
		}
		if err := writer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("close stalled capture writer: %v", err)
		}
	})
	os.Stdout = writer
	joins := 0
	abandonBlockedCapture(t, original, func() bool {
		joins++
		if os.Stdout != original {
			t.Error("stdout must be restored before joining capture")
		}
		if _, err := writer.Write([]byte("late output")); !errors.Is(err, os.ErrClosed) {
			t.Errorf("capture writer must be closed before join, got %v", err)
		}
		return true
	})
	if joins != 1 {
		t.Errorf("join called %d times, want 1", joins)
	}
	if os.Stdout != original {
		t.Error("stdout remains redirected after timeout recovery")
	}
}

func TestAbandonBlockedCaptureAlreadyRestored(t *testing.T) {
	original := os.Stdout
	joins := 0
	abandonBlockedCapture(t, original, func() bool {
		joins++
		if os.Stdout != original {
			t.Error("already restored stdout changed before join")
		}
		return true
	})
	if joins != 1 {
		t.Errorf("join called %d times, want 1", joins)
	}
	if _, err := original.Stat(); err != nil {
		t.Errorf("timeout recovery closed original stdout: %v", err)
	}
}
