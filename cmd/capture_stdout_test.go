package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Regression: captureRemoveStdout used to read the pipe only after fn
// returned, so output larger than the OS pipe buffer blocked fn forever.
func TestCaptureRemoveStdoutLargeOutputDoesNotBlock(t *testing.T) {
	original := os.Stdout
	want := strings.Repeat("x", 1<<20) // far beyond typical 64 KiB pipe buffers
	type result struct{ out string }
	done := make(chan result, 1)
	go func() {
		out := captureRemoveStdout(t, func() { fmt.Print(want) })
		done <- result{out: out}
	}()
	select {
	case res := <-done:
		if len(res.out) != len(want) || res.out != want {
			t.Fatalf("captured %d bytes, want %d", len(res.out), len(want))
		}
	case <-time.After(10 * time.Second):
		abandonBlockedCapture(t, original, func() bool {
			select {
			case <-done:
				return true
			case <-time.After(5 * time.Second):
				return false
			}
		})
		t.Fatal("captureRemoveStdout blocked on output larger than the pipe buffer")
	}
	if os.Stdout != original {
		t.Fatal("captureRemoveStdout did not restore stdout")
	}
}

// abandonBlockedCapture recovers from a capture that never returned: it closes
// the capture pipe writer still installed as os.Stdout so the blocked write
// fails, restores os.Stdout to original before the test fails, and joins the
// capturing goroutine through join so it does not outlive the test.
func abandonBlockedCapture(t *testing.T, original *os.File, join func() bool) {
	t.Helper()
	if capture := os.Stdout; capture != original {
		_ = capture.Close() // the capture helper closes it again; that error is ignored there
	}
	os.Stdout = original
	if !join() {
		t.Error("capture goroutine did not exit after its pipe writer was closed")
	}
}

// Keep the exact regression-test entry point while sharing the existing
// large-output assertions rather than duplicating them.
func TestCaptureRemoveStdoutLargeOutput(t *testing.T) {
	TestCaptureRemoveStdoutLargeOutputDoesNotBlock(t)
}

func TestCaptureRemoveStdoutFatalClosesDescriptors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaptureRemoveStdoutFatalChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PWD_MANAGER_CAPTURE_FATAL_CHILD=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("fatal capture child timed out: %v\n%s", ctx.Err(), out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("expected intentional test failure, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "capture fatal cleanup verified") {
		t.Fatalf("fatal capture did not close both descriptors and restore stdout:\n%s", out)
	}
}

func TestCaptureRemoveStdoutRestoresStdoutOnGoexit(t *testing.T) {
	original := os.Stdout
	done := make(chan struct{})
	go func() {
		defer close(done)
		captureRemoveStdout(t, func() {
			fmt.Print("partial")
			runtime.Goexit()
		})
	}()
	<-done
	if os.Stdout != original {
		t.Fatal("captureRemoveStdout did not restore stdout after Goexit")
	}
}
