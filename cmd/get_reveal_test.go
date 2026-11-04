package cmd

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// stubRevealEnv sets the reveal flag and terminal detection for one test.
func stubRevealEnv(t *testing.T, reveal, terminal bool) {
	t.Helper()
	origReveal, origTerm := getRevealFlag, stdoutIsTerminal
	t.Cleanup(func() { getRevealFlag, stdoutIsTerminal = origReveal, origTerm })
	getRevealFlag = reveal
	stdoutIsTerminal = func() bool { return terminal }
}

func TestGetPrintsPasswordOnlyToTerminalOrWithReveal(t *testing.T) {
	cases := []struct {
		name            string
		reveal, term    bool
		copy, wantPrint bool
		wantRevealError bool
	}{
		{name: "non-terminal without reveal", wantRevealError: true},
		{name: "non-terminal with reveal", reveal: true, wantPrint: true},
		{name: "terminal without reveal", term: true, wantPrint: true},
		{name: "terminal with reveal", reveal: true, term: true, wantPrint: true},
		{name: "copy non-terminal", copy: true},
		{name: "copy with reveal", copy: true, reveal: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubRevealEnv(t, tc.reveal, tc.term)
			fakeClipboard(t, nil, nil)
			stubGetClearer(t, time.Second, func(string, time.Duration) error { return nil })

			var err error
			out := captureStdout(t, func() {
				err = handleGetOutput("github", map[string]string{"github": "s3cr3t"}, tc.copy)
			})
			if tc.wantRevealError != errors.Is(err, errRevealRequired) {
				t.Fatalf("reveal error mismatch: got %v", err)
			}
			if !tc.wantRevealError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "s3cr3t") {
				t.Fatalf("error leaks the secret: %v", err)
			}
			if got := strings.Contains(out, "s3cr3t"); got != tc.wantPrint {
				t.Fatalf("password printed=%v, want %v (stdout %q)", got, tc.wantPrint, out)
			}
		})
	}
}

func TestGetRevealFlagRegistered(t *testing.T) {
	f := getCmd.Flags().Lookup("reveal")
	if f == nil || f.DefValue != "false" {
		t.Fatalf("expected --reveal flag defaulting to false, got %+v", f)
	}
}
