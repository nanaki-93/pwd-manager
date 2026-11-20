package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// daemonStopTimeout bounds how long `daemon --restart` waits for the
// previous daemon to exit after SIGTERM.
const daemonStopTimeout = 5 * time.Second

// daemonExitPollInterval is how often the previous daemon's liveness is
// checked while waiting for it to exit.
const daemonExitPollInterval = 50 * time.Millisecond

// daemonPidfilePath returns where the running daemon records its pid.
func daemonPidfilePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	return filepath.Join(dir, "pwd-manager", "daemon.pid"), nil
}

// daemonLogPath returns where a detached daemon writes its output: next to
// the pidfile at pidPath.
func daemonLogPath(pidPath string) string {
	return filepath.Join(filepath.Dir(pidPath), "daemon.log")
}

// readPidfile returns the pid recorded at path, or 0 when no pidfile exists.
func readPidfile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read pidfile %s: %w", path, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("parse pidfile %s: invalid pid %q", path, strings.TrimSpace(string(data)))
	}
	return pid, nil
}

// writePidfile records pid at path, creating its directory.
func writePidfile(path string, pid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create pidfile dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write pidfile %s: %w", path, err)
	}
	return nil
}

// removeOwnPidfile removes the pidfile at path only while it still records
// pid, so a daemon never deletes the pidfile of one that replaced it.
func removeOwnPidfile(path string, pid int) error {
	recorded, err := readPidfile(path)
	if err != nil {
		return err
	}
	if recorded != pid {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove pidfile %s: %w", path, err)
	}
	return nil
}

// runWithPidfile records this process in the pidfile at path while start
// runs, and removes the record when start returns.
func runWithPidfile(ctx context.Context, path string, start func(context.Context) error) error {
	pid := os.Getpid()
	if err := writePidfile(path, pid); err != nil {
		return err
	}
	startErr := start(ctx)
	if startErr != nil {
		startErr = fmt.Errorf("start daemon: %w", startErr)
	}
	return errors.Join(startErr, removeOwnPidfile(path, pid))
}

// stopRecordedDaemon sends SIGTERM to the daemon recorded at path and waits
// up to timeout for it to exit. A missing pidfile, a dead pid, or a pid now
// used by a process not named name (a reused pid) is left alone.
func stopRecordedDaemon(ctx context.Context, path, name string, timeout time.Duration) error {
	pid, err := readPidfile(path)
	if err != nil || pid == 0 || pid == os.Getpid() {
		return err
	}
	named, err := isProcessNamed(ctx, pid, name)
	if err != nil || !named {
		return err
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find daemon process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		return fmt.Errorf("terminate daemon process %d: %w", pid, err)
	}
	return waitForExit(ctx, proc, timeout)
}

// isProcessNamed reports whether pid is a running process whose executable
// is named name.
func isProcessNamed(ctx context.Context, pid int, name string) (bool, error) {
	out, err := exec.CommandContext(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil // ps exits non-zero when no such process exists
	}
	if err != nil {
		return false, fmt.Errorf("inspect process %d: %w", pid, err)
	}
	return filepath.Base(strings.TrimSpace(string(out))) == name, nil
}

// waitForExit polls until proc no longer exists, ctx is cancelled or
// timeout elapses.
func waitForExit(ctx context.Context, proc *os.Process, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(daemonExitPollInterval)
	defer ticker.Stop()
	for proc.Signal(syscall.Signal(0)) == nil {
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for daemon process %d to exit: %w", proc.Pid, ctx.Err())
		case <-deadline.C:
			return fmt.Errorf("daemon process %d did not exit within %s", proc.Pid, timeout)
		case <-ticker.C:
		}
	}
	return nil
}

// executableName returns the file name of the running binary, which a
// daemon started from the same install path shares.
func executableName() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	return filepath.Base(exe), nil
}
