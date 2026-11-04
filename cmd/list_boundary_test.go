package cmd

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestListTextUnicodeAndControlBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, input, escaped string }{
		{"printable unicode", "café 日本語 😀 �", "café 日本語 😀 �"},
		{"nul and delete", "a\x00\x7fb", `a\x00\x7fb`},
		{"C1 and line separator", "a\u009b\u2028b", `a\u009b\u2028b`},
		{"truncated utf8", "a\xe2\x82", `a\xe2\x82`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeListOutput(&out, map[string]string{tc.input: tc.input}, true); err != nil {
				t.Fatal(err)
			}
			if want := tc.escaped + ": " + tc.escaped + "\n"; out.String() != want {
				t.Fatalf("got %q, want %q", out.String(), want)
			}
		})
	}
}

// A short write without an error must still be surfaced by the buffering layer.
type listShortWriter struct{}

func (listShortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestListBufferedShortWrites(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(io.Writer, map[string]string, bool) error
	}{
		{"text", writeListOutput},
		{"json", writeListJSONOutput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.write(listShortWriter{}, map[string]string{"entry": "value"}, true)
			if !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("expected wrapped short write, got %v", err)
			}
		})
	}
}

func TestListBufferedFailureBeforeFinalFlush(t *testing.T) {
	for _, tc := range []struct {
		name    string
		write   func(io.Writer, map[string]string, bool) error
		context string
	}{
		{"text", writeListOutput, "write list output:"},
		{"json", writeListJSONOutput, "write list json output:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			boom := errors.New("output disconnected")
			saved := map[string]string{"a": strings.Repeat("x", 20000), "z": "last"}
			w := &failAfterNBytesWriter{remaining: 100, err: boom}
			err := tc.write(w, saved, true)
			if !errors.Is(err, boom) || !strings.Contains(err.Error(), tc.context) {
				t.Fatalf("expected contextual wrapped failure, got %v", err)
			}
			if w.buf.Len() != 100 || strings.Contains(w.buf.String(), "last") {
				t.Fatalf("unexpected partial output: %q", w.buf.String())
			}
			if saved["z"] != "last" || len(saved["a"]) != 20000 {
				t.Fatal("writer mutated caller's entries")
			}
		})
	}
}
