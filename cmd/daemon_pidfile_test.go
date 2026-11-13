package cmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRunWithPidfileLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache", "daemon.pid")
	startErr := errors.New("startup failed")
	err := runWithPidfile(context.Background(), path, func(context.Context) error {
		pid, err := readPidfile(path)
		if err != nil || pid != os.Getpid() {
			t.Fatalf("running pid = %d, error %v", pid, err)
		}
		return startErr
	})
	if !errors.Is(err, startErr) {
		t.Fatalf("error = %v, want startup failure", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("pidfile remains after exit: %v", err)
	}
}

func TestStopRecordedDaemonMissingAndInvalidPidfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := stopRecordedDaemon(context.Background(), path, "unused", time.Second); err != nil {
		t.Fatalf("missing pidfile: %v", err)
	}
	for _, value := range []string{"", "0", "-1", "not-a-pid"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if err := stopRecordedDaemon(context.Background(), path, "unused", time.Second); err == nil {
			t.Errorf("accepted invalid pid %q", value)
		}
	}
}

func TestStopRecordedDaemonWaitsForChildExit(t *testing.T) {
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	t.Cleanup(func() {
		_ = child.Process.Kill()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	})
	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := writePidfile(path, child.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if err := stopRecordedDaemon(context.Background(), path, "sleep", 3*time.Second); err != nil {
		t.Fatalf("stop child: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop returned before child exited")
	}
}

func TestStopRecordedDaemonDoesNotSignalDifferentProcess(t *testing.T) {
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := writePidfile(path, child.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if err := stopRecordedDaemon(context.Background(), path, "not-sleep", time.Second); err != nil {
		t.Fatal(err)
	}
	if err := child.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated process was terminated: %v", err)
	}
}
