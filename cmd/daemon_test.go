package cmd

import (
	"errors"
	"testing"
)

func TestDaemonCmdSurfacesStartFailure(t *testing.T) {
	orig := startDaemon
	t.Cleanup(func() { startDaemon = orig })
	startErr := errors.New("hotkey taken")
	startDaemon = func() error { return startErr }

	err := daemonCmd.RunE(daemonCmd, nil)
	if !errors.Is(err, startErr) {
		t.Fatalf("RunE error = %v, want wrapping %v", err, startErr)
	}
}

func TestDaemonCmdReturnsNilWhenStartSucceeds(t *testing.T) {
	orig := startDaemon
	t.Cleanup(func() { startDaemon = orig })
	startDaemon = func() error { return nil }

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
