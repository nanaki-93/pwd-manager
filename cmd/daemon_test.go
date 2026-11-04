package cmd

import (
	"context"
	"errors"
	"testing"
)

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
