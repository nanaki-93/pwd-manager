package cmd

import "testing"

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
