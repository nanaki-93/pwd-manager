package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Run the real parent assertion in isolation so its Fatalf can be observed.
func TestCaptureBaselineGuardHelper(t *testing.T) {
	fake := os.Getenv("PWD_MANAGER_BASELINE_GUARD_FAKE")
	if fake == "" {
		return
	}
	os.Args[0] = fake
	TestRemoveCaptureWarmBaseline(t)
}

func TestCaptureBaselineRequiresChildPass(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake executable uses a POSIX shell")
	}
	for _, tc := range []struct {
		name   string
		output string
		pass   bool
	}{
		{"empty", "", false},
		{"no_tests", "testing: warning: no tests to run\nPASS\n", false},
		{"other_child", "--- PASS: TestOtherChild (0.00s)\nPASS\n", false},
		{"expected_child", "=== RUN   TestRemoveCaptureWarmBaselineChild\n--- PASS: TestRemoveCaptureWarmBaselineChild (0.00s)\nPASS\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fake := filepath.Join(dir, "child")
			args := filepath.Join(dir, "args")
			script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$BASELINE_GUARD_ARGS\"\nprintf '%s' \"$BASELINE_GUARD_OUTPUT\"\n"
			if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaptureBaselineGuardHelper$", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(), "PWD_MANAGER_BASELINE_GUARD_FAKE="+fake,
				"BASELINE_GUARD_ARGS="+args, "BASELINE_GUARD_OUTPUT="+tc.output)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("helper timed out: %v\n%s", ctx.Err(), out)
			}
			if (err == nil) != tc.pass {
				t.Fatalf("helper error = %v, want pass=%v\n%s", err, tc.pass, out)
			}
			gotArgs, readErr := os.ReadFile(args)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !strings.Contains("\n"+string(gotArgs), "\n-test.v\n") {
				t.Errorf("child arguments lack -test.v: %s", gotArgs)
			}
			if !tc.pass {
				if !strings.Contains(string(out), "baseline child did not run TestRemoveCaptureWarmBaselineChild:") {
					t.Errorf("missing diagnostic: %s", out)
				}
				for _, line := range strings.Split(strings.TrimSpace(tc.output), "\n") {
					if !strings.Contains(string(out), line) {
						t.Errorf("diagnostic omitted child output line %q: %s", line, out)
					}
				}
			}
		})
	}
}
