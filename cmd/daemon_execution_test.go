package cmd

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/spf13/cobra"
)

func TestDaemonExecutionValidatesBeforeStarting(t *testing.T) {
	orig := startDaemon
	t.Cleanup(func() { startDaemon = orig })
	calls := 0
	startDaemon = func(context.Context) error {
		calls++
		return nil
	}

	for _, args := range [][]string{{"extra"}, {"--", "extra"}} {
		cmd := &cobra.Command{Use: daemonCmd.Use, Args: daemonCmd.Args, RunE: daemonCmd.RunE}
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("Execute(%q) accepted positional arguments", args)
		}
	}
	if calls != 0 {
		t.Fatalf("started daemon %d times for invalid arguments", calls)
	}
}

func TestDaemonExecutionReturnsStartupError(t *testing.T) {
	orig := startDaemon
	t.Cleanup(func() { startDaemon = orig })
	startErr := errors.New("registration failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	startDaemon = func(got context.Context) error {
		calls++
		if got != ctx {
			t.Error("ExecuteContext did not forward its context")
		}
		return startErr
	}
	cmd := &cobra.Command{Use: daemonCmd.Use, Args: daemonCmd.Args, RunE: daemonCmd.RunE}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{})
	if err := cmd.ExecuteContext(ctx); !errors.Is(err, startErr) {
		t.Fatalf("ExecuteContext error = %v, want wrapping %v", err, startErr)
	}
	if calls != 1 {
		t.Fatalf("startup calls = %d, want 1", calls)
	}
}
