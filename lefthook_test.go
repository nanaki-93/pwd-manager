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

	script, err := parseGitleaksRunScript(string(data))
	if err != nil {
		t.Fatalf("extract gitleaks run script from %s: %v", path, err)
	}
	return script
}

func lineIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// parseGitleaksRunScript returns the `run: |` block scalar that belongs to the
// gitleaks command. A `run: |` outside the gitleaks block is never accepted.
func parseGitleaksRunScript(data string) (string, error) {
	lines := strings.Split(data, "\n")
	gitleaksIndent := -1
	runStart := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if gitleaksIndent < 0 {
			if trimmed == "gitleaks:" {
				gitleaksIndent = lineIndent(line)
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if lineIndent(line) <= gitleaksIndent {
			return "", errors.New("gitleaks block ended before a `run: |` block was found")
		}
		if strings.HasPrefix(trimmed, "run: |") {
			runStart = i + 1
			break
		}
	}
	if gitleaksIndent < 0 {
		return "", errors.New("no `gitleaks:` command found")
	}
	if runStart < 0 {
		return "", errors.New("no `run: |` block found inside the gitleaks block")
	}
	script := strings.TrimSpace(strings.Join(blockScalarLines(lines[runStart:]), "\n"))
	if script == "" {
		return "", errors.New("gitleaks `run: |` block is empty")
	}
	return script, nil
}

// blockScalarLines returns the lines of a block scalar body, dedented by the
// indentation of its first non-blank line.
func blockScalarLines(lines []string) []string {
	runIndent := -1
	var out []string
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			out = append(out, "")
			continue
		}
		indent := lineIndent(line)
		if runIndent < 0 {
			runIndent = indent
		}
		if indent < runIndent {
			break
		}
		out = append(out, line[runIndent:])
	}
	return out
}

func runHookScript(t *testing.T, script, pathEnv, skipEnv string, extraEnv ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	cmd.Env = []string{"PATH=" + pathEnv}
	if skipEnv != "" {
		cmd.Env = append(cmd.Env, "SKIP_GITLEAKS="+skipEnv)
	}
	cmd.Env = append(cmd.Env, extraEnv...)

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

func TestParseGitleaksRunScriptScopedToGitleaksBlock(t *testing.T) {
	later := "    other:\n      run: |\n        echo other\n"
	tests := []struct {
		name string
		yaml string
	}{
		{"inline run", "  commands:\n    gitleaks:\n      run: gitleaks protect\n" + later},
		{"folded run", "  commands:\n    gitleaks:\n      run: >\n        gitleaks protect\n" + later},
		{"no run", "  commands:\n    gitleaks:\n      glob: \"*\"\n" + later},
		{"renamed", "  commands:\n    secrets:\n      run: gitleaks protect\n" + later},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			script, err := parseGitleaksRunScript(tc.yaml)
			if err == nil {
				t.Fatalf("parseGitleaksRunScript() = %q, want error", script)
			}
		})
	}

	script, err := parseGitleaksRunScript("  commands:\n    gitleaks:\n\n      run: |\n        echo ok\n" + later)
	if err != nil {
		t.Fatalf("parseGitleaksRunScript() error = %v", err)
	}
	if script != "echo ok" {
		t.Fatalf("parseGitleaksRunScript() = %q, want %q", script, "echo ok")
	}
}

func writeFakeGitleaks(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	stub := "#!/bin/sh\necho \"args:$*\"\nexit ${FAKE_GITLEAKS_EXIT:-0}\n"
	if err := os.WriteFile(filepath.Join(binDir, "gitleaks"), []byte(stub), 0o755); err != nil {
		t.Fatalf("write fake gitleaks: %v", err)
	}
	return binDir
}

func TestLefthookGitleaksLeakDetectedBlocksCommit(t *testing.T) {
	script := extractGitleaksRunScript(t, "lefthook.yml")
	binDir := writeFakeGitleaks(t)

	for _, skipEnv := range []string{"", "1"} {
		t.Run("SKIP_GITLEAKS="+skipEnv, func(t *testing.T) {
			code, stdout, stderr := runHookScript(t, script, binDir, skipEnv, "FAKE_GITLEAKS_EXIT=7")
			if code != 7 {
				t.Fatalf("exit code = %d, want scanner status 7 (stderr: %q)", code, stderr)
			}
			if !strings.Contains(stdout, "args:protect --staged") {
				t.Fatalf("stdout = %q, want scanner to have run", stdout)
			}
			for _, unwanted := range []string{"warning", "skipping", "success"} {
				if strings.Contains(strings.ToLower(stdout+stderr), unwanted) {
					t.Fatalf("output contains %q on leak detection (stdout: %q, stderr: %q)", unwanted, stdout, stderr)
				}
			}
		})
	}
}

func TestLefthookGitleaksPresent(t *testing.T) {
	script := extractGitleaksRunScript(t, "lefthook.yml")
	binDir := writeFakeGitleaks(t)

	code, stdout, stderr := runHookScript(t, script, binDir, "")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	wantArgs := "args:protect --staged --no-banner --redact"
	if strings.TrimSpace(stdout) != wantArgs {
		t.Fatalf("stdout = %q, want %q", strings.TrimSpace(stdout), wantArgs)
	}
}
