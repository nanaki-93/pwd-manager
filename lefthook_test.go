package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func extractGitleaksRunScript(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	lines := strings.Split(string(data), "\n")
	inGitleaks := false
	inRun := false
	runIndent := 0
	var scriptLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inGitleaks {
			if trimmed == "gitleaks:" {
				inGitleaks = true
			}
			continue
		}
		if !inRun {
			if strings.HasPrefix(trimmed, "run: |") {
				inRun = true
			}
			continue
		}
		if trimmed == "" {
			scriptLines = append(scriptLines, "")
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if runIndent == 0 {
			runIndent = indent
		}
		if indent < runIndent {
			break
		}
		scriptLines = append(scriptLines, line[runIndent:])
	}

	script := strings.TrimSpace(strings.Join(scriptLines, "\n"))
	if script == "" {
		t.Fatalf("failed to extract gitleaks run script from %s", path)
	}
	return script
}

func runHookScript(t *testing.T, script, pathEnv, skipEnv string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	cmd.Env = []string{"PATH=" + pathEnv}
	if skipEnv != "" {
		cmd.Env = append(cmd.Env, "SKIP_GITLEAKS="+skipEnv)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), stdout.String(), stderr.String()
	}
	t.Fatalf("unexpected execution error: %v", err)
	return -1, "", ""
}

func TestLefthookGitleaksMissingAndOptOut(t *testing.T) {
	script := extractGitleaksRunScript(t, "lefthook.yml")
	emptyBinDir := t.TempDir()

	tests := []struct {
		name       string
		skipEnv    string
		wantCode   int
		wantStderr string
	}{
		{
			name:       "fails closed when gitleaks is missing and SKIP_GITLEAKS is unset",
			skipEnv:    "",
			wantCode:   1,
			wantStderr: "error: gitleaks not found on PATH; install gitleaks or set SKIP_GITLEAKS=1 to skip staged secret scan",
		},
		{
			name:       "fails closed when SKIP_GITLEAKS is 0",
			skipEnv:    "0",
			wantCode:   1,
			wantStderr: "error: gitleaks not found on PATH",
		},
		{
			name:       "fails closed when SKIP_GITLEAKS is non-1 value",
			skipEnv:    "true",
			wantCode:   1,
			wantStderr: "error: gitleaks not found on PATH",
		},
		{
			name:       "succeeds with warning when SKIP_GITLEAKS is 1",
			skipEnv:    "1",
			wantCode:   0,
			wantStderr: "warning: gitleaks not found on PATH; skipping staged secret scan (SKIP_GITLEAKS=1)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runHookScript(t, script, emptyBinDir, tc.skipEnv)
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr: %q)", code, tc.wantCode, stderr)
			}
			if !strings.Contains(stderr, tc.wantStderr) {
				t.Fatalf("stderr = %q, want substring %q", stderr, tc.wantStderr)
			}
		})
	}
}

func TestLefthookGitleaksPresent(t *testing.T) {
	script := extractGitleaksRunScript(t, "lefthook.yml")
	binDir := t.TempDir()
	fakeGitleaks := filepath.Join(binDir, "gitleaks")

	stub := "#!/bin/sh\necho \"args:$*\"\nexit ${FAKE_GITLEAKS_EXIT:-0}\n"
	if err := os.WriteFile(fakeGitleaks, []byte(stub), 0o755); err != nil {
		t.Fatalf("write fake gitleaks: %v", err)
	}

	code, stdout, stderr := runHookScript(t, script, binDir, "")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	wantArgs := "args:protect --staged --no-banner --redact"
	if strings.TrimSpace(stdout) != wantArgs {
		t.Fatalf("stdout = %q, want %q", strings.TrimSpace(stdout), wantArgs)
	}
}
