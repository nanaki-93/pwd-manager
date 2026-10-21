package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type errWriter struct {
	err error
}

func (e errWriter) Write(_ []byte) (int, error) {
	return 0, e.err
}

type failAfterNWriter struct {
	remaining int
	err       error
	buf       bytes.Buffer
}

func (w *failAfterNWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, w.err
	}
	w.remaining--
	return w.buf.Write(p)
}

func TestWriteListOutput_MasksByDefault(t *testing.T) {
	saved := map[string]string{
		"github": "super-secret-1",
		"email":  "hunter2",
	}

	var buf bytes.Buffer
	if err := writeListOutput(&buf, saved, false); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := buf.String()
	want := "email: ********\ngithub: ********\n"
	if got != want {
		t.Fatalf("unexpected output: got %q, want %q", got, want)
	}
	if strings.Contains(got, "super-secret-1") || strings.Contains(got, "hunter2") {
		t.Fatalf("plaintext password leaked in masked output: %q", got)
	}
}

func TestWriteListOutput_ShowsPlaintextWhenFlagSet(t *testing.T) {
	saved := map[string]string{
		"github": "super-secret-1",
		"email":  "hunter2",
	}

	var buf bytes.Buffer
	if err := writeListOutput(&buf, saved, true); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := buf.String()
	want := "email: hunter2\ngithub: super-secret-1\n"
	if got != want {
		t.Fatalf("unexpected output: got %q, want %q", got, want)
	}
}

func TestWriteListOutput_EmptyAndNilMap(t *testing.T) {
	for _, tc := range []struct {
		name          string
		saved         map[string]string
		showPlaintext bool
	}{
		{name: "nil map masked", saved: nil, showPlaintext: false},
		{name: "nil map plaintext", saved: nil, showPlaintext: true},
		{name: "empty map masked", saved: map[string]string{}, showPlaintext: false},
		{name: "empty map plaintext", saved: map[string]string{}, showPlaintext: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeListOutput(&buf, tc.saved, tc.showPlaintext); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if buf.Len() != 0 {
				t.Fatalf("expected empty output, got %q", buf.String())
			}
		})
	}
}

func TestWriteListOutput_BoundaryValuesAndSorting(t *testing.T) {
	saved := map[string]string{
		"z-account": "",
		"a-account": "p@ss:w0rd!",
		"m-account": "********",
	}

	var maskedBuf bytes.Buffer
	if err := writeListOutput(&maskedBuf, saved, false); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	wantMasked := "a-account: ********\nm-account: ********\nz-account: ********\n"
	if maskedBuf.String() != wantMasked {
		t.Fatalf("unexpected masked output: got %q, want %q", maskedBuf.String(), wantMasked)
	}

	var plainBuf bytes.Buffer
	if err := writeListOutput(&plainBuf, saved, true); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	wantPlain := "a-account: p@ss:w0rd!\nm-account: ********\nz-account: \n"
	if plainBuf.String() != wantPlain {
		t.Fatalf("unexpected plaintext output: got %q, want %q", plainBuf.String(), wantPlain)
	}
}

func TestWriteListOutput_PropagatesWriteError(t *testing.T) {
	saved := map[string]string{"github": "super-secret-1"}
	boom := errors.New("broken pipe")

	err := writeListOutput(errWriter{err: boom}, saved, false)
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped error %v, got %v", boom, err)
	}
	if !strings.Contains(err.Error(), "write list output:") {
		t.Fatalf("expected error context 'write list output:', got %q", err.Error())
	}
}

func TestWriteListOutput_MidStreamWriteError(t *testing.T) {
	saved := map[string]string{
		"first":  "secret-1",
		"second": "secret-2",
	}
	boom := errors.New("short write on second entry")
	w := &failAfterNWriter{remaining: 1, err: boom}

	err := writeListOutput(w, saved, false)
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped error %v, got %v", boom, err)
	}
	if w.buf.String() != "first: ********\n" {
		t.Fatalf("unexpected partial output before error: %q", w.buf.String())
	}
}

func TestListCmd_ShowFlagRegistered(t *testing.T) {
	flag := listCmd.Flags().Lookup("show")
	if flag == nil {
		t.Fatal("expected --show flag to be registered on listCmd")
	}
	if flag.Shorthand != "s" {
		t.Fatalf("expected shorthand 's', got %q", flag.Shorthand)
	}
	if flag.DefValue != "false" {
		t.Fatalf("expected default value 'false', got %q", flag.DefValue)
	}
}

func TestListCmd_ShowFlagParsing(t *testing.T) {
	orig := listShowFlag
	t.Cleanup(func() {
		_ = listCmd.Flags().Set("show", "false")
		listShowFlag = orig
	})

	if err := listCmd.ParseFlags([]string{"-s"}); err != nil {
		t.Fatalf("unexpected error parsing -s: %v", err)
	}
	if !listShowFlag {
		t.Fatal("expected listShowFlag to be true after parsing -s")
	}

	if err := listCmd.ParseFlags([]string{"--show=false"}); err != nil {
		t.Fatalf("unexpected error parsing --show=false: %v", err)
	}
	if listShowFlag {
		t.Fatal("expected listShowFlag to be false after parsing --show=false")
	}
}
