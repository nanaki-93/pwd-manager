package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestReadPwdNameRejectsControlAndEscapeBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{name: "ANSI escape sequence", input: "evil\x1b[2J\x1b]0;pwned\x07name\n"},
		{name: "bare escape byte", input: "a\x1bb\n"},
		{name: "embedded NUL", input: "a\x00b\n"},
		{name: "carriage return", input: "fake\rname\n"},
		{name: "embedded tab", input: "a\tb\n"},
		{name: "C1 control CSI", input: "a\u009bb\n"},
		{name: "bidi override", input: "a‮b\n"},
		{name: "invalid UTF-8", input: "a\xffb\n"},
		{name: "too long", input: strings.Repeat("x", maxPwdNameLen+1) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, err := readPwdName(strings.NewReader(tc.input))
			if err == nil {
				t.Fatalf("expected rejection, got name %q", name)
			}
			if !errors.Is(err, errInvalidPwdName) {
				t.Fatalf("expected errInvalidPwdName, got %q", err.Error())
			}
			if name != "" {
				t.Fatalf("expected empty name on rejection, got %q", name)
			}
			if strings.ContainsAny(err.Error(), "\x1b\x00\r\a") {
				t.Fatalf("error message must not echo raw control bytes: %q", err.Error())
			}
		})
	}
}

func TestReadPwdNameAcceptsPrintableUnicodeAtMaxLength(t *testing.T) {
	for _, input := range []string{
		"conto bancario è già",
		strings.Repeat("é", maxPwdNameLen),
	} {
		name, err := readPwdName(strings.NewReader(input + "\n"))
		if err != nil {
			t.Fatalf("expected %q to be accepted, got %v", input, err)
		}
		if name != input {
			t.Fatalf("expected %q, got %q", input, name)
		}
	}
}
