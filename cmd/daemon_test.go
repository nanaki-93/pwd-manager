package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDaemonDetachForwardsFlagsWithoutStartingDaemon(t *testing.T) {
	oldSpawn, oldStart := spawnDetached, startDaemon
	oldDetach, oldRestart, oldConfig := detachDaemon, restartDaemon, cfgFile
	t.Cleanup(func() {
		spawnDetached, startDaemon = oldSpawn, oldStart
		detachDaemon, restartDaemon, cfgFile = oldDetach, oldRestart, oldConfig
		daemonCmd.SetOut(nil)
	})
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	detachDaemon, restartDaemon, cfgFile = true, true, "config with spaces.toml"
	var args []string
	var logPath string
	spawnDetached = func(a []string, path string) (int, error) {
		args, logPath = a, path
		return 12345, nil
	}
	startDaemon = func(context.Context) error { t.Error("started daemon in parent"); return nil }
	var out bytes.Buffer
	daemonCmd.SetOut(&out)
	if err := daemonCmd.RunE(daemonCmd, nil); err != nil {
		t.Fatal(err)
	}
	want := []string{"daemon", "--restart", "--config", cfgFile}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("child args = %q, want %q", args, want)
	}
	pidPath, err := daemonPidfilePath()
	if err != nil {
		t.Fatal(err)
	}
	if logPath != filepath.Join(filepath.Dir(pidPath), "daemon.log") {
		t.Errorf("log path = %q", logPath)
	}
	if !strings.Contains(out.String(), "12345") || !strings.Contains(out.String(), logPath) {
		t.Errorf("notice = %q", out.String())
	}
}

type daemonCtxKey struct{}

func TestDaemonCmdPassesCommandContext(t *testing.T) {
	orig := startDaemon
	t.Cleanup(func() { startDaemon = orig })
	var got context.Context
	startDaemon = func(ctx context.Context) error {
		got = ctx
		return nil
	}

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), daemonCtxKey{}, "cmd"))
	daemonCmd.SetContext(ctx)
	t.Cleanup(func() { daemonCmd.SetContext(context.Background()) })

	if err := daemonCmd.RunE(daemonCmd, nil); err != nil {
		t.Fatalf("RunE error = %v, want nil", err)
	}
	if got == nil || got.Value(daemonCtxKey{}) != "cmd" {
		t.Fatal("startDaemon did not receive the command's context")
	}
	cancel()
	select {
	case <-got.Done():
	default:
		t.Fatal("cancelling the command context did not reach startDaemon")
	}
}

func TestDaemonCmdSurfacesStartFailure(t *testing.T) {
	orig := startDaemon
	t.Cleanup(func() { startDaemon = orig })
	startErr := errors.New("hotkey taken")
	startDaemon = func(context.Context) error { return startErr }

	err := daemonCmd.RunE(daemonCmd, nil)
	if !errors.Is(err, startErr) {
		t.Fatalf("RunE error = %v, want wrapping %v", err, startErr)
	}
}

func TestDaemonCmdReturnsNilWhenStartSucceeds(t *testing.T) {
	orig := startDaemon
	t.Cleanup(func() { startDaemon = orig })
	startDaemon = func(context.Context) error { return nil }

	if err := daemonCmd.RunE(daemonCmd, nil); err != nil {
		t.Fatalf("RunE error = %v, want nil", err)
	}
}

func TestDaemonCmdRejectsArgs(t *testing.T) {
	if daemonCmd.Args == nil {
		t.Fatal("daemonCmd.Args is nil; extra arguments would be accepted")
	}
	if err := daemonCmd.Args(daemonCmd, []string{"foo"}); err == nil {
		t.Fatal("daemonCmd.Args accepted positional argument \"foo\"")
	}
	if err := daemonCmd.Args(daemonCmd, []string{"foo", "bar"}); err == nil {
		t.Fatal("daemonCmd.Args accepted two positional arguments")
	}
}

func TestDaemonCmdAcceptsNoArgs(t *testing.T) {
	if daemonCmd.Args == nil {
		t.Fatal("daemonCmd.Args is nil")
	}
	if err := daemonCmd.Args(daemonCmd, []string{}); err != nil {
		t.Fatalf("daemonCmd.Args rejected zero arguments: %v", err)
	}
	if err := daemonCmd.Args(daemonCmd, nil); err != nil {
		t.Fatalf("daemonCmd.Args rejected nil arguments: %v", err)
	}
}
