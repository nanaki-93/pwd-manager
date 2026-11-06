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

// whitespaceGlobPatterns returns the `whitespace` command's glob from
// lefthook.yml with its single {a,b} brace group expanded.
func whitespaceGlobPatterns(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("lefthook.yml")
	if err != nil {
		t.Fatalf("read lefthook.yml: %v", err)
	}
	glob, err := whitespaceGlob(string(data))
	if err != nil {
		t.Fatalf("lefthook.yml: %v", err)
	}
	open, closing := strings.Index(glob, "{"), strings.Index(glob, "}")
	if open < 0 || closing < open {
		return []string{glob}
	}
	var patterns []string
	for _, alt := range strings.Split(glob[open+1:closing], ",") {
		patterns = append(patterns, glob[:open]+alt+glob[closing+1:])
	}
	return patterns
}

// whitespaceGlob returns the `glob:` value inside the `whitespace:` command
// block, stopping at the next line indented no deeper than `whitespace:`.
func whitespaceGlob(config string) (string, error) {
	blockIndent := -1
	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if blockIndent < 0 {
			if trimmed == "whitespace:" {
				blockIndent = indent
			}
			continue
		}
		if indent <= blockIndent {
			break
		}
		if strings.HasPrefix(trimmed, "glob:") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "glob:")), `"'`), nil
		}
	}
	return "", errors.New("no glob found inside the whitespace command block")
}

func TestWhitespaceGlobIgnoresLaterCommandGlob(t *testing.T) {
	config := "pre-commit:\n  commands:\n    whitespace:\n      run: git diff --check\n    gitleaks:\n      glob: \"*.go\"\n"
	if glob, err := whitespaceGlob(config); err == nil {
		t.Fatalf("whitespaceGlob = %q, want error for whitespace block without glob", glob)
	}
}

func TestWhitespaceGlobReadsOwnBlock(t *testing.T) {
	config := "pre-commit:\n  commands:\n    whitespace:\n      glob: \"*.{go,yml}\"\n      run: x\n    gitleaks:\n      glob: \"*\"\n"
	glob, err := whitespaceGlob(config)
	if err != nil || glob != "*.{go,yml}" {
		t.Fatalf("whitespaceGlob = %q, %v; want \"*.{go,yml}\"", glob, err)
	}
}

func whitespaceGlobMatches(t *testing.T, name string) bool {
	t.Helper()
	for _, pattern := range whitespaceGlobPatterns(t) {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			t.Fatalf("match %q against %q: %v", name, pattern, err)
		}
		if matched {
			return true
		}
	}
	return false
}

func TestLefthookWhitespaceGlobSkipsMarkdownHardBreaks(t *testing.T) {
	if whitespaceGlobMatches(t, "README.md") {
		t.Fatal("whitespace glob matches README.md; Markdown two-space hard breaks would fail git diff --check")
	}
}

func TestLefthookWhitespaceGlobStillChecksGo(t *testing.T) {
	if !whitespaceGlobMatches(t, "main.go") {
		t.Fatal("whitespace glob does not match main.go; trailing whitespace in Go would go unchecked")
	}
}

// Exercise the configured command against a real index, including a mixed batch
// where Markdown must not hide a Go whitespace error.
func TestLefthookWhitespaceStagedFiles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		wantErr bool
	}{
		{"markdown_hard_break_only", map[string]string{"README.md": "hard break  \nnext line\n"}, false},
		{"go_trailing_space", map[string]string{"main.go": "package main \n"}, true},
		{"markdown_and_clean_go", map[string]string{"README.md": "hard break  \n", "main.go": "package main\n"}, false},
		{"markdown_and_bad_go", map[string]string{"README.md": "hard break  \n", "main.go": "package main\t\n"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			git := func(args ...string) {
				t.Helper()
				cmd := exec.CommandContext(ctx, "git", args...)
				cmd.Dir = dir
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			git("init", "--quiet")
			git("config", "core.whitespace", "blank-at-eol")
			var selected []string
			for name, content := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				git("add", "--", name)
				if whitespaceGlobMatches(t, name) {
					selected = append(selected, name)
				}
			}
			if len(selected) == 0 {
				if tc.wantErr {
					t.Fatal("no files selected for whitespace check")
				}
				return // Lefthook skips commands with no matching staged files.
			}
			data, err := os.ReadFile("lefthook.yml")
			if err != nil {
				t.Fatal(err)
			}
			start := strings.Index(string(data), "    whitespace:\n")
			block := strings.SplitN(string(data)[start:], "\n    gitleaks:", 2)[0]
			_, run, found := strings.Cut(block, "run: ")
			if !found {
				t.Fatal("whitespace run command missing")
			}
			script := strings.ReplaceAll(strings.TrimSpace(run), "{staged_files}", strings.Join(selected, " "))
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if err != nil && !errors.As(err, &exitErr) {
				t.Fatalf("execute whitespace command: %v", err)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("whitespace error = %v, want failure %v; output: %s", err, tc.wantErr, out)
			}
		})
	}
}
