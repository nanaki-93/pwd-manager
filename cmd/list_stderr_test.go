package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Regression: text-mode list failures were reported on stderr only in JSON
// mode; text mode relied on utils.ManageErrorAndExit printing to stdout.
func TestRunListCmd_TextModeReportsErrorOnStderr(t *testing.T) {
	boom := errors.New("stdout write failure")
	var errBuf bytes.Buffer
	err := runListCmd(errWriter{err: boom}, &errBuf, map[string]string{"a": "b"}, false, false, false)
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped %v, got %v", boom, err)
	}
	if got := errBuf.String(); strings.Count(got, "Error: ") != 1 || !strings.Contains(got, "stdout write failure") {
		t.Fatalf("expected one Error line on stderr, got %q", got)
	}
}

func TestRunListCmd_NonTTYAllowedOutputCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name        string
		show        bool
		asJSON      bool
		allowNonTTY bool
		want        string
	}{
		{"text plaintext override", true, false, true, "github: test-password\n"},
		{"json masked without override", false, true, false, "{\n  \"github\": \"********\"\n}\n"},
		{"json masked with override", false, true, true, "{\n  \"github\": \"********\"\n}\n"},
		{"text masked with override", false, false, true, "github: ********\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			err := runListCmd(&out, &errOut, map[string]string{"github": "test-password"}, tc.show, tc.asJSON, tc.allowNonTTY)
			if err != nil {
				t.Fatalf("allowed output failed: %v", err)
			}
			if out.String() != tc.want {
				t.Fatalf("stdout = %q, want %q", out.String(), tc.want)
			}
			if errOut.Len() != 0 {
				t.Fatalf("unexpected stderr: %q", errOut.String())
			}
		})
	}
}

func TestExecListCmd_FailureReportedOnceOnStderrOnly(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		var code []int
		prevExit := listExitFunc
		listExitFunc = func(c int) { code = append(code, c) }
		restoreUtilsExit := setUtilsExit(func(int) { t.Error("utils exit must not be used by list") })
		prevShow, prevJSON, prevAllow := listShowFlag, listJSONFlag, listAllowNonTTYFlag
		listShowFlag, listJSONFlag, listAllowNonTTYFlag = true, asJSON, false

		var out, errOut bytes.Buffer
		c := &cobra.Command{}
		c.SetOut(&out)
		c.SetErr(&errOut)
		stdout := captureRemoveStdout(t, func() { execListCmd(c, nil) })

		listExitFunc = prevExit
		restoreUtilsExit()
		listShowFlag, listJSONFlag, listAllowNonTTYFlag = prevShow, prevJSON, prevAllow

		if len(code) != 1 || code[0] != 1 {
			t.Fatalf("json=%v: expected one exit(1), got %v", asJSON, code)
		}
		if out.Len() != 0 || stdout != "" {
			t.Fatalf("json=%v: stdout must stay clean, got %q / %q", asJSON, out.String(), stdout)
		}
		if got := errOut.String(); strings.Count(got, "Error: ") != 1 || !strings.Contains(got, "not a terminal") {
			t.Fatalf("json=%v: expected one Error line on stderr, got %q", asJSON, got)
		}
	}
}
