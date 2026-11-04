package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Keep descriptor assertions isolated from files opened by other tests.
func TestRemoveCaptureWarmBaseline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRemoveCaptureWarmBaselineChild$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "PWD_MANAGER_CAPTURE_BASELINE_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("baseline child failed (context: %v): %v\n%s", ctx.Err(), err, out)
	}
	// A filter that matches nothing also exits 0; require the child's own PASS line.
	if !bytes.Contains(out, []byte("--- PASS: TestRemoveCaptureWarmBaselineChild")) {
		t.Fatalf("baseline child did not run TestRemoveCaptureWarmBaselineChild:\n%s", out)
	}
}

func TestRemoveCaptureWarmBaselineChild(t *testing.T) {
	if os.Getenv("PWD_MANAGER_CAPTURE_BASELINE_CHILD") != "1" {
		return
	}
	warmUpRemoveCapturePipe(t)
	before := removeCaptureDescriptorCount(t)
	// Repeated warm-ups must close both ends, not inflate the baseline.
	for i := 0; i < 3; i++ {
		warmUpRemoveCapturePipe(t)
		if got := removeCaptureDescriptorCount(t); got != before {
			t.Fatalf("warm-up %d: descriptors = %d, want %d", i, got, before)
		}
	}
	for _, keepReader := range []bool{true, false} {
		checkRemoveCaptureSingleEndpoint(t, before, keepReader)
	}
}

// A single surviving endpoint must remain visible after warm-up, whether it
// is the reader or writer. This guards the sensitivity of the fatal test's
// count comparison independently of its explicit writer.Stat assertion.
func checkRemoveCaptureSingleEndpoint(t *testing.T, before int, keepReader bool) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("boundary pipe: %v", err)
	}
	keep, closeFirst := writer, reader
	if keepReader {
		keep, closeFirst = reader, writer
	}
	t.Cleanup(func() {
		if err := keep.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("cleanup endpoint: %v", err)
		}
	})
	if err := closeFirst.Close(); err != nil {
		t.Fatalf("close opposite endpoint: %v", err)
	}
	if got := removeCaptureDescriptorCount(t); got != before+1 {
		t.Errorf("keepReader=%v: descriptors = %d, want %d", keepReader, got, before+1)
	}
	if err := keep.Close(); err != nil {
		t.Fatalf("close remaining endpoint: %v", err)
	}
	if got := removeCaptureDescriptorCount(t); got != before {
		t.Errorf("keepReader=%v: closed descriptors = %d, want %d", keepReader, got, before)
	}
}
