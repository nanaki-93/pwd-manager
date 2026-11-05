package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// whitespaceGlobPatterns returns the `whitespace` command's glob from
// lefthook.yml with its single {a,b} brace group expanded.
func whitespaceGlobPatterns(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("lefthook.yml")
	if err != nil {
		t.Fatalf("read lefthook.yml: %v", err)
	}
	inWhitespace := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "whitespace:" {
			inWhitespace = true
			continue
		}
		if !inWhitespace || !strings.HasPrefix(trimmed, "glob:") {
			continue
		}
		glob := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "glob:")), `"'`)
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
	t.Fatal("no glob found for the whitespace command in lefthook.yml")
	return nil
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
