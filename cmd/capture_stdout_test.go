package cmd

import (
	"fmt"
	"os"
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
		t.Fatal("captureRemoveStdout blocked on output larger than the pipe buffer")
	}
	if os.Stdout != original {
		t.Fatal("captureRemoveStdout did not restore stdout")
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
