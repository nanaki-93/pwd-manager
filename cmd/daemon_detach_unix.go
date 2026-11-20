//go:build unix

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// startDetachedProcess re-executes this binary with args in a new session,
// so it has no controlling terminal and survives the terminal closing. Its
// stdin reads from /dev/null and its output is appended to logPath. The child
// is released, not waited for: it deliberately outlives this process and any
// context, so it is started without one.
func startDetachedProcess(args []string, logPath string) (pid int, err error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("locate executable: %w", err)
	}
	logFile, err := openDaemonLog(logPath)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, closeFile(logFile)) }()
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer func() { err = errors.Join(err, closeFile(devNull)) }()

	child := detachedCommand(exe, args, devNull, logFile)
	if err := child.Start(); err != nil {
		return 0, fmt.Errorf("run %s: %w", exe, err)
	}
	pid = child.Process.Pid
	if err := child.Process.Release(); err != nil {
		return pid, fmt.Errorf("release daemon process %d: %w", pid, err)
	}
	return pid, nil
}

// detachedCommand builds the command running exe with args as the leader of
// a new session, reading stdin and writing stdout and stderr to the given
// files.
func detachedCommand(exe string, args []string, stdin, output *os.File) *exec.Cmd {
	child := exec.Command(exe, args...)
	child.Stdin = stdin
	child.Stdout = output
	child.Stderr = output
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return child
}

// openDaemonLog opens logPath for appending, creating it with mode 0600 in
// a 0700 directory.
func openDaemonLog(logPath string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return nil, fmt.Errorf("create daemon log dir: %w", err)
	}
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open daemon log %s: %w", logPath, err)
	}
	return f, nil
}

// closeFile closes f, naming it in the error.
func closeFile(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", f.Name(), err)
	}
	return nil
}
