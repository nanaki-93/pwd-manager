package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// resetFlagToDefault restores a flag registered on cmd to its default value
// and clears pflag's Changed marker, so tests that parse flags on the shared
// command do not leak state into later tests.
func resetFlagToDefault(cmd *cobra.Command, name string) error {
	f := cmd.Flags().Lookup(name)
	if f == nil {
		return fmt.Errorf("reset flag %q on %q: flag not registered", name, cmd.Name())
	}
	if err := f.Value.Set(f.DefValue); err != nil {
		return fmt.Errorf("reset flag %q on %q to %q: %w", name, cmd.Name(), f.DefValue, err)
	}
	f.Changed = false
	return nil
}

type errWriter struct {
	err error
}

func (e errWriter) Write(_ []byte) (int, error) {
	return 0, e.err
}

// failAfterNBytesWriter accepts at most remaining bytes and then fails, so
// the partial output it records does not depend on how many Write calls the
// writer under test makes.
type failAfterNBytesWriter struct {
	remaining int
	err       error
	buf       bytes.Buffer
}

func (w *failAfterNBytesWriter) Write(p []byte) (int, error) {
	if len(p) <= w.remaining {
		w.remaining -= len(p)
		return w.buf.Write(p)
	}
	n, _ := w.buf.Write(p[:w.remaining])
	w.remaining = 0
	return n, w.err
}

// byteSplitWriter forwards each byte in its own Write call.
type byteSplitWriter struct {
	w io.Writer
}

func (s byteSplitWriter) Write(p []byte) (int, error) {
	for i := range p {
		if _, err := s.w.Write(p[i : i+1]); err != nil {
			return i, err
		}
	}
	return len(p), nil
}

// wholeBufferWriter collects all output and forwards it in a single Write.
type wholeBufferWriter struct {
	w   io.Writer
	buf bytes.Buffer
}

func (b *wholeBufferWriter) Write(p []byte) (int, error) {
	return b.buf.Write(p)
}

func (b *wholeBufferWriter) flush() error {
	_, err := b.w.Write(b.buf.Bytes())
	return err
}

// countingWriter records how many Write calls reach it.
type countingWriter struct {
	calls int
	buf   bytes.Buffer
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.calls++
	return c.buf.Write(p)
}

// A short write without an error must still be surfaced by the buffering layer.
type listShortWriter struct{}

func (listShortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

type resetRejectingValue struct {
	err error
}

func (v *resetRejectingValue) String() string { return "current" }
func (v *resetRejectingValue) Type() string   { return "reset-rejecting" }
func (v *resetRejectingValue) Set(string) error {
	return v.err
}

// listOutputMode names a list writer and the context its errors carry.
type listOutputMode struct {
	name    string
	write   func(io.Writer, map[string]string, bool) error
	context string
}

func listOutputModes() []listOutputMode {
	return []listOutputMode{
		{"text", writeListOutput, "write list output:"},
		{"json", writeListJSONOutput, "write list json output:"},
	}
}

func TestWriteListOutput_SortsAndMasksEntries(t *testing.T) {
	saved := map[string]string{
		"github":    "super-secret-1",
		"email":     "hunter2",
		"z-account": "",
		"a-account": "p@ss:w0rd!",
		"m-account": "********",
	}
	for _, tc := range []struct {
		name string
		show bool
		want string
	}{
		{"masked by default", false, "a-account: ********\nemail: ********\ngithub: ********\nm-account: ********\nz-account: ********\n"},
		{"plaintext when shown", true, "a-account: p@ss:w0rd!\nemail: hunter2\ngithub: super-secret-1\nm-account: ********\nz-account: \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeListOutput(&buf, saved, tc.show); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if got := buf.String(); got != tc.want {
				t.Fatalf("unexpected output: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestListWriters_EmptyAndNilMap(t *testing.T) {
	wantByMode := map[string]string{"text": "", "json": "{}\n"}
	for _, mode := range listOutputModes() {
		for _, saved := range []map[string]string{nil, {}} {
			for _, show := range []bool{false, true} {
				var buf bytes.Buffer
				if err := mode.write(&buf, saved, show); err != nil {
					t.Fatalf("%s nil=%v show=%v: expected no error, got %v", mode.name, saved == nil, show, err)
				}
				if got := buf.String(); got != wantByMode[mode.name] {
					t.Fatalf("%s nil=%v show=%v: got %q, want %q", mode.name, saved == nil, show, got, wantByMode[mode.name])
				}
			}
		}
	}
}

func TestWriteListOutput_EscapesKeysAndValues(t *testing.T) {
	for _, tc := range []struct{ name, key, value, wantKey, wantValue string }{
		{"terminal escapes", "evil\x1b[2J\rname\xe2\x80\xae", "val\x07\x1b]0;pwn\x07\xff", `evil\x1b[2J\rname\` + `u202e`, `val\a\x1b]0;pwn\a\xff`},
		{"separator in key", "a: b", "v1", `a\: b`, "v1"},
		{"newline and separator in key", "x\nfake: entry", "v2", `x\nfake\: entry`, "v2"},
		{"backslash in key", `back\nslash`, "v3", `back\\nslash`, "v3"},
		{"colon without space", "plain-key:no-sep", "v4", "plain-key:no-sep", "v4"},
		{"printable unicode", "café 日本語 😀 �", "café 日本語 😀 �", "café 日本語 😀 �", "café 日本語 😀 �"},
		{"nul and delete", "a\x00\x7fb", "a\x00\x7fb", `a\x00\x7fb`, `a\x00\x7fb`},
		{"C1 and line separator", "a\xc2\x9b\xe2\x80\xa8b", "a\xc2\x9b\xe2\x80\xa8b", `a\` + `u009b\` + `u2028b`, `a\` + `u009b\` + `u2028b`},
		{"truncated utf8", "a\xe2\x82", "a\xe2\x82", `a\xe2\x82`, `a\xe2\x82`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, show := range []bool{false, true} {
				var buf bytes.Buffer
				if err := writeListOutput(&buf, map[string]string{tc.key: tc.value}, show); err != nil {
					t.Fatalf("show=%v: expected no error, got %v", show, err)
				}
				wantValue := maskedPasswordPlaceholder
				if show {
					wantValue = tc.wantValue
				}
				if want := tc.wantKey + ": " + wantValue + "\n"; buf.String() != want {
					t.Fatalf("show=%v: got %q, want %q", show, buf.String(), want)
				}
			}
		})
	}
}

func TestSanitizeForTerminal_PrintableASCIIUnchangedWithoutAllocating(t *testing.T) {
	var printable string
	for c := byte(0x20); c <= 0x7e; c++ {
		printable += string(c)
	}
	for _, s := range []string{"", " ", "~", printable, "github.com/user: Pa55-w0rd ~!@#$%^&*()"} {
		allocs := testing.AllocsPerRun(100, func() {
			if got := sanitizeForTerminal(s); got != s {
				t.Fatalf("sanitizeForTerminal(%q) = %q, want unchanged", s, got)
			}
		})
		if allocs != 0 {
			t.Errorf("input %q: allocations = %v, want zero", s, allocs)
		}
	}
}

func TestSanitizeForTerminal_EscapesOutsidePrintableASCII(t *testing.T) {
	for in, want := range map[string]string{
		"a\x1b[31mb": `a\x1b[31mb`,
		"tab\there":  `tab\there`,
		"del\x7f":    `del\x7f`,
		"bad\xff":    `bad\xff`,
		"héllo":      "héllo",
		"\x1f ~":     `\x1f ~`,
		" ~\x7f":     ` ~\x7f`,
		" ~\u0080":   ` ~\u0080`,
	} {
		if got := sanitizeForTerminal(in); got != want {
			t.Errorf("sanitizeForTerminal(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteListOutput_BuffersEntriesIntoFewWrites(t *testing.T) {
	saved := make(map[string]string, 100)
	for i := 0; i < 100; i++ {
		saved[fmt.Sprintf("entry-%03d", i)] = "secret"
	}

	w := &countingWriter{}
	if err := writeListOutput(w, saved, false); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if w.calls != 1 {
		t.Fatalf("expected 1 Write call for small output, got %d", w.calls)
	}
	if !strings.HasPrefix(w.buf.String(), "entry-000: ********\n") ||
		!strings.HasSuffix(w.buf.String(), "entry-099: ********\n") {
		t.Fatalf("unexpected output: %q", w.buf.String())
	}
}

func TestListWriters_FlushErrorIsWrapped(t *testing.T) {
	boom := errors.New("broken pipe")
	for _, mode := range listOutputModes() {
		for _, show := range []bool{false, true} {
			err := mode.write(errWriter{err: boom}, map[string]string{"github": "super-secret-1"}, show)
			if !errors.Is(err, boom) {
				t.Fatalf("%s show=%v: expected wrapped error %v, got %v", mode.name, show, boom, err)
			}
			if !strings.Contains(err.Error(), mode.context+" flush:") {
				t.Fatalf("%s show=%v: expected flush error context, got %q", mode.name, show, err.Error())
			}
		}
	}
}

func TestListWriters_ShortWritesAreReported(t *testing.T) {
	for _, mode := range listOutputModes() {
		t.Run(mode.name, func(t *testing.T) {
			err := mode.write(listShortWriter{}, map[string]string{"entry": "value"}, true)
			if !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("expected wrapped short write, got %v", err)
			}
		})
	}
}

func TestListWriters_FailureBeforeFinalFlush(t *testing.T) {
	for _, mode := range listOutputModes() {
		t.Run(mode.name, func(t *testing.T) {
			boom := errors.New("output disconnected")
			saved := map[string]string{"a": strings.Repeat("x", 20000), "z": "last"}
			w := &failAfterNBytesWriter{remaining: 100, err: boom}
			err := mode.write(w, saved, true)
			if !errors.Is(err, boom) || !strings.Contains(err.Error(), mode.context) {
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

func TestWriteListOutput_MidStreamWriteErrorIndependentOfWriteCalls(t *testing.T) {
	saved := map[string]string{
		"first":  "secret-1",
		"second": "secret-2",
	}
	boom := errors.New("short write on second entry")
	wantPartial := "first: ********\n"

	for _, tc := range []struct {
		name  string
		write func(t *testing.T, sink io.Writer) error
	}{
		{"direct writes", func(_ *testing.T, sink io.Writer) error { return writeListOutput(sink, saved, false) }},
		{"split into single-byte writes", func(_ *testing.T, sink io.Writer) error {
			return writeListOutput(byteSplitWriter{w: sink}, saved, false)
		}},
		{"whole output in one write", func(t *testing.T, sink io.Writer) error {
			bw := &wholeBufferWriter{w: sink}
			if err := writeListOutput(bw, saved, false); err != nil {
				t.Fatalf("expected no error while buffering, got %v", err)
			}
			return bw.flush()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &failAfterNBytesWriter{remaining: len(wantPartial), err: boom}
			if err := tc.write(t, sink); !errors.Is(err, boom) {
				t.Fatalf("expected wrapped error %v, got %v", boom, err)
			}
			if sink.buf.String() != wantPartial {
				t.Fatalf("unexpected partial output before error: %q", sink.buf.String())
			}
		})
	}
}

func TestFailAfterNBytesWriter_ByteBudgetBoundaries(t *testing.T) {
	boom := errors.New("byte budget exhausted")
	for _, tc := range []struct {
		name      string
		remaining int
		input     string
		want      string
		wantErr   bool
	}{
		{name: "zero budget", input: "abc", wantErr: true},
		{name: "partial write", remaining: 2, input: "abcd", want: "ab", wantErr: true},
		{name: "exact budget", remaining: 3, input: "abc", want: "abc"},
		{name: "below budget", remaining: 4, input: "abc", want: "abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &failAfterNBytesWriter{remaining: tc.remaining, err: boom}
			n, err := w.Write([]byte(tc.input))
			if n != len(tc.want) || w.buf.String() != tc.want {
				t.Fatalf("Write = %d, buffer %q; want %d, %q", n, w.buf.String(), len(tc.want), tc.want)
			}
			if tc.wantErr && !errors.Is(err, boom) {
				t.Fatalf("expected sentinel error, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected write error: %v", err)
			}
			if w.remaining == 0 {
				n, err = w.Write([]byte("next"))
				if n != 0 || !errors.Is(err, boom) || w.buf.String() != tc.want {
					t.Fatalf("exhausted writer accepted data: n=%d err=%v buffer=%q", n, err, w.buf.String())
				}
			}
		})
	}
}

func TestListCmd_FlagsRegistered(t *testing.T) {
	for _, tc := range []struct{ name, shorthand string }{
		{"show", "s"},
		{"json", ""},
		{"allow-non-tty", ""},
	} {
		flag := listCmd.Flags().Lookup(tc.name)
		if flag == nil {
			t.Fatalf("expected --%s flag to be registered on listCmd", tc.name)
		}
		if flag.Shorthand != tc.shorthand {
			t.Fatalf("--%s: expected shorthand %q, got %q", tc.name, tc.shorthand, flag.Shorthand)
		}
		if flag.DefValue != "false" {
			t.Fatalf("--%s: expected default value 'false', got %q", tc.name, flag.DefValue)
		}
	}
}

func TestListCmd_FlagParsing(t *testing.T) {
	for _, tc := range []struct {
		name, enable, disable string
		value                 *bool
	}{
		{"show", "-s", "--show=false", &listShowFlag},
		{"json", "--json", "--json=false", &listJSONFlag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := *tc.value
			t.Cleanup(func() {
				if err := resetFlagToDefault(listCmd, tc.name); err != nil {
					t.Errorf("cleanup: %v", err)
				}
				*tc.value = orig
			})
			if err := listCmd.ParseFlags([]string{tc.enable}); err != nil || !*tc.value {
				t.Fatalf("parsing %s: err=%v, value=%v; want true", tc.enable, err, *tc.value)
			}
			if err := listCmd.ParseFlags([]string{tc.disable}); err != nil || *tc.value {
				t.Fatalf("parsing %s: err=%v, value=%v; want false", tc.disable, err, *tc.value)
			}
		})
	}
}

func TestResetFlagToDefault_RestoresValueAndChanged(t *testing.T) {
	orig := listJSONFlag
	t.Cleanup(func() { listJSONFlag = orig })

	if err := listCmd.ParseFlags([]string{"--json"}); err != nil {
		t.Fatalf("unexpected error parsing --json: %v", err)
	}
	if err := resetFlagToDefault(listCmd, "json"); err != nil {
		t.Fatalf("unexpected reset error: %v", err)
	}
	if listJSONFlag {
		t.Fatal("expected listJSONFlag to be false after reset")
	}
	if listCmd.Flags().Changed("json") {
		t.Fatal("expected Changed marker for --json to be cleared after reset")
	}
}

func TestResetFlagToDefault_ReportsUnknownFlag(t *testing.T) {
	err := resetFlagToDefault(listCmd, "no-such-flag")
	if err == nil {
		t.Fatal("expected error when resetting an unregistered flag")
	}
	if !strings.Contains(err.Error(), "no-such-flag") {
		t.Fatalf("expected error to name the flag, got %v", err)
	}
}

func TestResetFlagToDefault_PropagatesValueResetFailure(t *testing.T) {
	boom := errors.New("reset rejected")
	cmd := &cobra.Command{Use: "isolated-list"}
	cmd.Flags().Var(&resetRejectingValue{err: boom}, "json", "test flag")
	flag := cmd.Flags().Lookup("json")
	flag.Changed = true

	err := resetFlagToDefault(cmd, "json")
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped reset error %v, got %v", boom, err)
	}
	for _, context := range []string{"json", "isolated-list", "current"} {
		if !strings.Contains(err.Error(), context) {
			t.Errorf("reset error %q lacks context %q", err, context)
		}
	}
	if !flag.Changed {
		t.Fatal("failed reset must not mark the flag unchanged")
	}
}

func TestCheckPlaintextOutputAllowed_Policy(t *testing.T) {
	orig := isTerminalWriter
	t.Cleanup(func() { isTerminalWriter = orig })

	cases := []struct {
		name             string
		tty, show, allow bool
		wantRefused      bool
	}{
		{"masked non-tty", false, false, false, false},
		{"show non-tty refused", false, true, false, true},
		{"show non-tty with override", false, true, true, false},
		{"show tty", true, true, false, false},
	}
	for _, tc := range cases {
		tty := tc.tty
		isTerminalWriter = func(io.Writer) bool { return tty }
		err := checkPlaintextOutputAllowed(&bytes.Buffer{}, tc.show, tc.allow)
		if tc.wantRefused != errors.Is(err, errPlaintextNotTTY) {
			t.Fatalf("%s: got err %v, wantRefused=%v", tc.name, err, tc.wantRefused)
		}
	}
}

func TestCheckPlaintextOutputAllowed_RealNonTTYWriters(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer f.Close()
	for _, w := range []io.Writer{&bytes.Buffer{}, f} {
		if err := checkPlaintextOutputAllowed(w, true, false); !errors.Is(err, errPlaintextNotTTY) {
			t.Fatalf("%T: expected refusal, got %v", w, err)
		}
		if err := checkPlaintextOutputAllowed(w, false, false); err != nil {
			t.Fatalf("%T: masked output must be allowed, got %v", w, err)
		}
	}
}

func TestRunListCmd_AllowedOutputGoesToStdoutOnly(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		show, asJSON, allowNonTTY bool
		want                      string
	}{
		{"text masked without override", false, false, false, "github: ********\n"},
		{"text masked with override", false, false, true, "github: ********\n"},
		{"text plaintext override", true, false, true, "github: test-password\n"},
		{"json masked without override", false, true, false, "{\n  \"github\": \"********\"\n}\n"},
		{"json masked with override", false, true, true, "{\n  \"github\": \"********\"\n}\n"},
		{"json plaintext override", true, true, true, "{\n  \"github\": \"test-password\"\n}\n"},
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

func TestRunListCmd_WriteFailureReportedOnceOnStderr(t *testing.T) {
	boom := errors.New("stdout write failure")
	for _, asJSON := range []bool{false, true} {
		var errBuf bytes.Buffer
		err := runListCmd(errWriter{err: boom}, &errBuf, map[string]string{"a": "b"}, false, asJSON, false)
		if !errors.Is(err, boom) {
			t.Fatalf("json=%v: expected wrapped %v, got %v", asJSON, boom, err)
		}
		if got := errBuf.String(); strings.Count(got, "Error: ") != 1 || !strings.Contains(got, "stdout write failure") {
			t.Fatalf("json=%v: expected one Error line on stderr, got %q", asJSON, got)
		}
	}
}

func TestRunListCmd_RefusesPlaintextToNonTTYWithoutOverride(t *testing.T) {
	saved := map[string]string{"github": "super-secret-1"}
	for _, asJSON := range []bool{false, true} {
		var outBuf, errBuf bytes.Buffer
		err := runListCmd(&outBuf, &errBuf, saved, true, asJSON, false)
		if !errors.Is(err, errPlaintextNotTTY) {
			t.Fatalf("json=%v: expected errPlaintextNotTTY, got %v", asJSON, err)
		}
		if outBuf.Len() != 0 {
			t.Fatalf("json=%v: expected empty stdout, got %q", asJSON, outBuf.String())
		}
		if !strings.Contains(errBuf.String(), "refusing to print plaintext") {
			t.Fatalf("json=%v: expected refusal on stderr, got %q", asJSON, errBuf.String())
		}
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

func BenchmarkWriteListOutput(b *testing.B) {
	entries := make(map[string]string, 10000)
	for i := 0; i < 10000; i++ {
		entries[fmt.Sprintf("service-%05d.example.com", i)] = fmt.Sprintf("password-%05d", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := writeListOutput(io.Discard, entries, true); err != nil {
			b.Fatal(err)
		}
	}
}
