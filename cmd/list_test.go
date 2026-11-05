package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

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

func TestWriteListOutput_EscapesControlCharacters(t *testing.T) {
	saved := map[string]string{
		"evil\x1b[2J\rname\xe2\x80\xae": "val\x07\x1b]0;pwn\x07\xff",
	}

	for _, show := range []bool{false, true} {
		var buf bytes.Buffer
		if err := writeListOutput(&buf, saved, show); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		got := buf.String()
		body := strings.TrimSuffix(got, "\n")
		for _, r := range body {
			if r < 0x20 || r == 0x7f || r == 0x202e || r == utf8.RuneError {
				t.Fatalf("show=%v: output contains unescaped rune %U: %q", show, r, got)
			}
		}
		if !strings.HasPrefix(got, `evil\x1b[2J\rname`+"\\"+`u202e: `) {
			t.Fatalf("show=%v: name not escaped as expected: %q", show, got)
		}
		if show && !strings.HasSuffix(got, `: val\a\x1b]0;pwn\a\xff`+"\n") {
			t.Fatalf("value not escaped as expected: %q", got)
		}
	}
}

func TestWriteListOutput_EscapesSeparatorAndNewlineInKeys(t *testing.T) {
	saved := map[string]string{
		"a: b":             "v1",
		"x\nfake: entry":   "v2",
		`back\nslash`:      "v3",
		"plain-key:no-sep": "v4",
	}

	var buf bytes.Buffer
	if err := writeListOutput(&buf, saved, true); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	want := `a\: b: v1` + "\n" +
		`back\\nslash: v3` + "\n" +
		`plain-key:no-sep: v4` + "\n" +
		`x\nfake\: entry: v2` + "\n"
	if got := buf.String(); got != want {
		t.Fatalf("unexpected output:\n got %q\nwant %q", got, want)
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

// countingWriter records how many Write calls reach it.
type countingWriter struct {
	calls int
	buf   bytes.Buffer
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.calls++
	return c.buf.Write(p)
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

func TestWriteListOutput_FlushErrorIsWrapped(t *testing.T) {
	saved := map[string]string{"github": "super-secret-1"}
	boom := errors.New("broken pipe")

	err := writeListOutput(errWriter{err: boom}, saved, false)
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped error %v, got %v", boom, err)
	}
	if !strings.Contains(err.Error(), "write list output: flush:") {
		t.Fatalf("expected flush error context, got %q", err.Error())
	}
}

func TestWriteListOutput_MidStreamWriteError(t *testing.T) {
	saved := map[string]string{
		"first":  "secret-1",
		"second": "secret-2",
	}
	boom := errors.New("short write on second entry")
	wantPartial := "first: ********\n"
	w := &failAfterNBytesWriter{remaining: len(wantPartial), err: boom}

	err := writeListOutput(w, saved, false)
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped error %v, got %v", boom, err)
	}
	if w.buf.String() != wantPartial {
		t.Fatalf("unexpected partial output before error: %q", w.buf.String())
	}
}

func TestWriteListOutput_MidStreamWriteErrorIndependentOfWriteCalls(t *testing.T) {
	saved := map[string]string{
		"first":  "secret-1",
		"second": "secret-2",
	}
	boom := errors.New("short write on second entry")
	wantPartial := "first: ********\n"

	t.Run("split into single-byte writes", func(t *testing.T) {
		sink := &failAfterNBytesWriter{remaining: len(wantPartial), err: boom}
		err := writeListOutput(byteSplitWriter{w: sink}, saved, false)
		if !errors.Is(err, boom) {
			t.Fatalf("expected wrapped error %v, got %v", boom, err)
		}
		if sink.buf.String() != wantPartial {
			t.Fatalf("unexpected partial output before error: %q", sink.buf.String())
		}
	})

	t.Run("whole output in one write", func(t *testing.T) {
		sink := &failAfterNBytesWriter{remaining: len(wantPartial), err: boom}
		bw := &wholeBufferWriter{w: sink}
		if err := writeListOutput(bw, saved, false); err != nil {
			t.Fatalf("expected no error while buffering, got %v", err)
		}
		if err := bw.flush(); !errors.Is(err, boom) {
			t.Fatalf("expected error %v on flush, got %v", boom, err)
		}
		if sink.buf.String() != wantPartial {
			t.Fatalf("unexpected partial output before error: %q", sink.buf.String())
		}
	})
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
		if err := resetFlagToDefault(listCmd, "show"); err != nil {
			t.Errorf("cleanup: %v", err)
		}
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

func TestListCmd_JSONFlagRegistered(t *testing.T) {
	flag := listCmd.Flags().Lookup("json")
	if flag == nil {
		flag = listCmd.PersistentFlags().Lookup("json")
	}
	if flag == nil {
		t.Fatal("expected --json flag to be registered on listCmd")
	}
	if flag.DefValue != "false" {
		t.Fatalf("expected default value 'false', got %q", flag.DefValue)
	}
}

func TestListCmd_JSONFlagParsing(t *testing.T) {
	orig := listJSONFlag
	t.Cleanup(func() {
		if err := resetFlagToDefault(listCmd, "json"); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		listJSONFlag = orig
	})

	if err := listCmd.ParseFlags([]string{"--json"}); err != nil {
		t.Fatalf("unexpected error parsing --json: %v", err)
	}
	if !listJSONFlag {
		t.Fatal("expected listJSONFlag to be true after parsing --json")
	}

	if err := listCmd.ParseFlags([]string{"--json=false"}); err != nil {
		t.Fatalf("unexpected error parsing --json=false: %v", err)
	}
	if listJSONFlag {
		t.Fatal("expected listJSONFlag to be false after parsing --json=false")
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

func TestWriteListJSONOutput_MasksByDefaultAndValidStructure(t *testing.T) {
	saved := map[string]string{
		"github": "super-secret-1",
		"email":  "hunter2",
	}

	var buf bytes.Buffer
	if err := writeListJSONOutput(&buf, saved, false); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	raw := buf.String()
	wantFormatted := "{\n  \"email\": \"********\",\n  \"github\": \"********\"\n}\n"
	if raw != wantFormatted {
		t.Fatalf("unexpected formatted JSON: got %q, want %q", raw, wantFormatted)
	}
	if strings.Contains(raw, "super-secret-1") || strings.Contains(raw, "hunter2") {
		t.Fatalf("plaintext password leaked in masked JSON output: %q", raw)
	}

	var parsed map[string]string
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(parsed) != 2 || parsed["email"] != maskedPasswordPlaceholder || parsed["github"] != maskedPasswordPlaceholder {
		t.Fatalf("unexpected parsed JSON map: %#v", parsed)
	}
}

func TestWriteListJSONOutput_ShowsPlaintextWhenFlagSet(t *testing.T) {
	saved := map[string]string{
		"github":  "super-secret-1",
		"email":   "hunter2",
		"special": "p@ss:w0rd!",
	}

	var buf bytes.Buffer
	if err := writeListJSONOutput(&buf, saved, true); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if err := checkJSONEntries(buf.Bytes(), saved); err != nil {
		t.Fatalf("unexpected plaintext JSON output %q: %v", buf.String(), err)
	}
}

// checkJSONEntries reports whether raw is a JSON object holding exactly the
// entries of want: no missing, changed, extra or duplicated keys.
func checkJSONEntries(raw []byte, want map[string]string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return fmt.Errorf("expected JSON object start, got %v (err=%v)", tok, err)
	}
	seen := make(map[string]bool, len(want))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("read key: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("expected string key, got %v", tok)
		}
		var val string
		if err := dec.Decode(&val); err != nil {
			return fmt.Errorf("decode value for key %q: %w", key, err)
		}
		if seen[key] {
			return fmt.Errorf("duplicated key %q", key)
		}
		seen[key] = true
		exp, ok := want[key]
		if !ok {
			return fmt.Errorf("unexpected extra key %q", key)
		}
		if val != exp {
			return fmt.Errorf("for key %q: got %q, want %q", key, val, exp)
		}
	}
	if len(seen) != len(want) {
		return fmt.Errorf("got %d keys, want %d", len(seen), len(want))
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("read object end: %w", err)
	}
	return nil
}

func TestCheckJSONEntries_RejectsExtraDuplicateAndMissingKeys(t *testing.T) {
	want := map[string]string{"email": "hunter2", "github": "s1"}
	for _, tc := range []struct {
		name string
		raw  string
		ok   bool
	}{
		{name: "exact", raw: `{"email":"hunter2","github":"s1"}`, ok: true},
		{name: "extra key", raw: `{"email":"hunter2","github":"s1","bank":"x"}`},
		{name: "duplicated key", raw: `{"email":"hunter2","github":"s1","email":"hunter2"}`},
		{name: "missing key", raw: `{"email":"hunter2"}`},
		{name: "changed value", raw: `{"email":"hunter2","github":"s2"}`},
		{name: "not an object", raw: `["email"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkJSONEntries([]byte(tc.raw), want)
			if tc.ok && err != nil {
				t.Fatalf("expected match, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected mismatch for %s", tc.raw)
			}
		})
	}
}

func TestWriteListJSONOutput_EmptyAndNilMap(t *testing.T) {
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
			if err := writeListJSONOutput(&buf, tc.saved, tc.showPlaintext); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if buf.String() != "{}\n" {
				t.Fatalf("expected empty JSON object, got %q", buf.String())
			}
			var parsed map[string]string
			if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
			if len(parsed) != 0 {
				t.Fatalf("expected empty parsed map, got %#v", parsed)
			}
		})
	}
}

func TestWriteListJSONOutput_PropagatesWriteError(t *testing.T) {
	saved := map[string]string{"github": "super-secret-1"}
	boom := errors.New("broken pipe")

	err := writeListJSONOutput(errWriter{err: boom}, saved, false)
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped error %v, got %v", boom, err)
	}
	if !strings.Contains(err.Error(), "write list json output:") {
		t.Fatalf("expected error context 'write list json output:', got %q", err.Error())
	}
}

func TestWriteListJSONOutput_MatchesMarshalIndentByteForByte(t *testing.T) {
	saved := map[string]string{}
	saved["github"] = "super-secret-1"
	saved["<html>&'\""] = "a<b>&c\"d\\e"
	saved["bad\xffutf8"] = "v\xfe"
	saved["ünïcode "] = "line\nbreak\t\x01"
	saved[""] = ""
	saved["plain-key:no-sep"] = "p@ss:w0rd!"
	for _, show := range []bool{false, true} {
		entries := make(map[string]string, len(saved))
		for k, v := range saved {
			entries[k] = maskedPasswordPlaceholder
			if show {
				entries[k] = v
			}
		}
		want, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			t.Fatalf("marshal reference: %v", err)
		}
		var buf bytes.Buffer
		if err := writeListJSONOutput(&buf, saved, show); err != nil {
			t.Fatalf("show=%v: expected no error, got %v", show, err)
		}
		if got := buf.String(); got != string(want)+"\n" {
			t.Fatalf("show=%v: output differs:\n got %q\nwant %q", show, got, string(want)+"\n")
		}
	}
}

// maxWriteWriter records the largest single Write it receives.
type maxWriteWriter struct {
	max   int
	total int
}

func (m *maxWriteWriter) Write(p []byte) (int, error) {
	if len(p) > m.max {
		m.max = len(p)
	}
	m.total += len(p)
	return len(p), nil
}

func TestWriteListJSONOutput_StreamsLargeVaultInBoundedWrites(t *testing.T) {
	saved := make(map[string]string, 5000)
	for i := 0; i < 5000; i++ {
		saved[fmt.Sprintf("entry-%05d", i)] = strings.Repeat("s", 32)
	}
	for _, show := range []bool{false, true} {
		w := &maxWriteWriter{}
		if err := writeListJSONOutput(w, saved, show); err != nil {
			t.Fatalf("show=%v: expected no error, got %v", show, err)
		}
		if w.total < 64*1024 {
			t.Fatalf("show=%v: payload too small for the test: %d bytes", show, w.total)
		}
		if w.max > 4096 {
			t.Fatalf("show=%v: largest single write was %d bytes of %d; output is not streamed", show, w.max, w.total)
		}
	}
}

func TestWriteListJSONOutput_FlushErrorIsWrapped(t *testing.T) {
	boom := errors.New("broken pipe")
	err := writeListJSONOutput(errWriter{err: boom}, map[string]string{"a": "b"}, true)
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped error %v, got %v", boom, err)
	}
	if !strings.Contains(err.Error(), "write list json output: flush:") {
		t.Fatalf("expected flush error context, got %q", err.Error())
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

func TestListCmd_HasAllowNonTTYFlag(t *testing.T) {
	fl := listCmd.Flags().Lookup("allow-non-tty")
	if fl == nil || fl.DefValue != "false" {
		t.Fatalf("expected --allow-non-tty flag defaulting to false, got %+v", fl)
	}
}

func TestRunListCmd_DefaultPlainTextWhenJSONOmitted(t *testing.T) {
	saved := map[string]string{
		"github": "super-secret-1",
		"email":  "hunter2",
	}

	var outBuf, errBuf bytes.Buffer
	if err := runListCmd(&outBuf, &errBuf, saved, false, false, false); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	want := "email: ********\ngithub: ********\n"
	if outBuf.String() != want {
		t.Fatalf("unexpected stdout: got %q, want %q", outBuf.String(), want)
	}
	if errBuf.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", errBuf.String())
	}
}

func TestRunListCmd_JSONModeWritesStdoutAndRoutesErrorsToStderr(t *testing.T) {
	saved := map[string]string{
		"github": "super-secret-1",
	}

	var outBuf, errBuf bytes.Buffer
	if err := runListCmd(&outBuf, &errBuf, saved, true, true, true); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if errBuf.Len() != 0 {
		t.Fatalf("expected empty stderr on success, got %q", errBuf.String())
	}
	var parsed map[string]string
	if err := json.Unmarshal(outBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid JSON on stdout, got error: %v", err)
	}
	if parsed["github"] != "super-secret-1" {
		t.Fatalf("unexpected value for github: %q", parsed["github"])
	}

	// Verify error routing to stderr when JSON output fails.
	boom := errors.New("stdout write failure")
	var failErrBuf bytes.Buffer
	err := runListCmd(errWriter{err: boom}, &failErrBuf, saved, false, true, false)
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped error %v, got %v", boom, err)
	}
	if !strings.Contains(failErrBuf.String(), "stdout write failure") {
		t.Fatalf("expected error message written to stderr, got %q", failErrBuf.String())
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
