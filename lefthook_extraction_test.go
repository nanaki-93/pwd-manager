package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseGitleaksRunScriptIndentBoundaries(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"same indentation run", "    gitleaks:\n    run: |\n      echo unrelated\n"},
		{"lower indentation run", "    gitleaks:\n  run: |\n    echo unrelated\n"},
		{"lower indentation command", "    gitleaks:\n      glob: '*'\n  other:\n    run: |\n      echo unrelated\n"},
		{"end of file", "    gitleaks:\n      glob: '*'"},
		{"blank tail", "    gitleaks:\n\n   \n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			script, err := parseGitleaksRunScript(tc.yaml)
			if err == nil || script != "" {
				t.Fatalf("parseGitleaksRunScript() = (%q, %v), want empty script and error", script, err)
			}
		})
	}
}

// Fatalf terminates a testing goroutine, so exercise the real *testing.T in a
// child test process rather than replacing the extractor's caller contract.
func TestExtractGitleaksRunScriptFatalNamesFile(t *testing.T) {
	const fixtureEnv = "LEFTHOOK_EXTRACTION_FATAL_FIXTURE"
	const returnedSentinel = "extractor returned instead of calling Fatalf"
	if path := os.Getenv(fixtureEnv); path != "" {
		extractGitleaksRunScript(t, path)
		t.Fatal(returnedSentinel)
	}
	for _, yaml := range []string{
		"commands:\n  gitleaks:\n    glob: '*'\n",
		"commands:\n  gitleaks:\n    run: echo inline\n  other:\n    run: |\n      echo unrelated\n",
	} {
		path := filepath.Join(t.TempDir(), "missing-gitleaks-run.yml")
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExtractGitleaksRunScriptFatalNamesFile$")
		cmd.Env = append(os.Environ(), fixtureEnv+"="+path)
		output, err := cmd.CombinedOutput()
		cancel()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			t.Fatalf("child test error = %v, want test failure (output: %s)", err, output)
		}
		want := "extract gitleaks run script from " + path + ":"
		if !strings.Contains(string(output), want) {
			t.Fatalf("child output = %s, want diagnostic containing %q", output, want)
		}
		if strings.Contains(string(output), returnedSentinel) {
			t.Fatalf("child output = %s, want extractor to stop via Fatalf, not return", output)
		}
	}
}
