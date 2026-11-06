package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { _ = r.Close() })

	// Drain the pipe concurrently so output larger than the OS pipe buffer
	// cannot block fn forever.
	var buf bytes.Buffer
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(&buf, r)
	}()
	defer func() {
		// Close is idempotent here: a second call only returns an ignored error.
		// Closing the writer ends the drain, so it never outlives the capture.
		_ = w.Close()
		os.Stdout = oldStdout
		<-drained
	}()

	fn()

	_ = w.Close()
	os.Stdout = oldStdout
	<-drained
	return buf.String()
}

func captureGetStderr(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	defer func() {
		os.Stderr = old
		if err := f.Close(); err != nil {
			t.Errorf("close stderr capture: %v", err)
		}
	}()
	os.Stderr = f
	fn()
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// stubRevealEnv sets the reveal flag and terminal detection for one test.
func stubRevealEnv(t *testing.T, reveal, terminal bool) {
	t.Helper()
	origReveal, origTerm := getRevealFlag, stdoutIsTerminal
	t.Cleanup(func() { getRevealFlag, stdoutIsTerminal = origReveal, origTerm })
	getRevealFlag = reveal
	stdoutIsTerminal = func() bool { return terminal }
}

// stubGetClearer swaps getClipboardClearer and getClearAfterFlag for the test.
func stubGetClearer(t *testing.T, delay time.Duration, fn func(pwd string, d time.Duration) error) {
	t.Helper()
	origClearer, origDelay := getClipboardClearer, getClearAfterFlag
	t.Cleanup(func() { getClipboardClearer, getClearAfterFlag = origClearer, origDelay })
	getClipboardClearer, getClearAfterFlag = fn, delay
}

func TestGetAndAddFlagsRegistered(t *testing.T) {
	for _, tc := range []struct {
		cmd                 *cobra.Command
		flag, short, defVal string
	}{
		{cmd: getCmd, flag: "copy", short: "c", defVal: "false"},
		{cmd: addCmd, flag: "copy", short: "c", defVal: "false"},
		{cmd: getCmd, flag: "clear-after", defVal: addClipboardClearDelay.String()},
		{cmd: getCmd, flag: "reveal", defVal: "false"},
	} {
		f := tc.cmd.Flags().Lookup(tc.flag)
		if f == nil || f.Shorthand != tc.short || f.DefValue != tc.defVal {
			t.Errorf("%s --%s: want shorthand %q default %q, got %+v", tc.cmd.Name(), tc.flag, tc.short, tc.defVal, f)
		}
	}
}

// parseFlagsIsolated parses args against copies of the command's flag
// definitions in a fresh flag set, so the shared command's flag set keeps its
// own parse state and Changed markers. The copies share the bound Values, so
// the package variables still receive the parsed values; those are restored
// to their pre-test values when the test ends.
func parseFlagsIsolated(t *testing.T, cmd *cobra.Command, args []string) error {
	t.Helper()
	fs := pflag.NewFlagSet(cmd.Name()+"-isolated", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		clone := *f
		clone.Changed = false
		fs.AddFlag(&clone)
		old := f.Value.String()
		t.Cleanup(func() {
			if err := f.Value.Set(old); err != nil {
				t.Errorf("restore flag %q of %s: %v", f.Name, cmd.Name(), err)
			}
		})
	})
	return fs.Parse(args)
}

func TestGetAndAddCopyFlagParsing(t *testing.T) {
	if err := parseFlagsIsolated(t, getCmd, []string{"-n", "github", "-c"}); err != nil {
		t.Fatalf("unexpected parse error on getCmd -c: %v", err)
	}
	if !getCopyFlag || nameFlag != "github" {
		t.Fatalf("expected getCopyFlag=true and nameFlag='github', got %v and %q", getCopyFlag, nameFlag)
	}

	if err := parseFlagsIsolated(t, addCmd, []string{"--copy"}); err != nil {
		t.Fatalf("unexpected parse error on addCmd --copy: %v", err)
	}
	if !addCopyFlag {
		t.Fatalf("expected addCopyFlag=true after parsing --copy")
	}
}

type flagState struct {
	value   string
	changed bool
}

func snapshotFlagSet(fs *pflag.FlagSet) (bool, []string, map[string]flagState) {
	states := map[string]flagState{}
	fs.VisitAll(func(f *pflag.Flag) {
		states[f.Name] = flagState{value: f.Value.String(), changed: f.Changed}
	})
	return fs.Parsed(), append([]string(nil), fs.Args()...), states
}

// TestGetAndAddCopyFlagParsingRestoresSharedState guards against
// TestGetAndAddCopyFlagParsing leaking parse state into the package-level
// getCmd/addCmd flag sets or resetting non-default values to their defaults.
func TestGetAndAddCopyFlagParsingRestoresSharedState(t *testing.T) {
	oldGet, oldAdd, oldName := getCopyFlag, addCopyFlag, nameFlag
	t.Cleanup(func() { getCopyFlag, addCopyFlag, nameFlag = oldGet, oldAdd, oldName })
	getCopyFlag, addCopyFlag, nameFlag = true, true, "existing name"

	flagSets := map[string]*pflag.FlagSet{"get": getCmd.Flags(), "add": addCmd.Flags()}
	type snap struct {
		parsed bool
		args   []string
		states map[string]flagState
	}
	take := func(fs *pflag.FlagSet) snap {
		p, a, s := snapshotFlagSet(fs)
		return snap{parsed: p, args: a, states: s}
	}
	before := map[string]snap{}
	for name, fs := range flagSets {
		before[name] = take(fs)
	}

	for i := 0; i < 2; i++ {
		t.Run("parse", TestGetAndAddCopyFlagParsing)
		if !getCopyFlag || !addCopyFlag || nameFlag != "existing name" {
			t.Fatalf("iteration %d did not restore prior values: get=%v add=%v name=%q",
				i, getCopyFlag, addCopyFlag, nameFlag)
		}
	}
	for name, fs := range flagSets {
		if after := take(fs); !reflect.DeepEqual(after, before[name]) {
			t.Errorf("%s flag set state changed from %+v to %+v", name, before[name], after)
		}
	}
}

func TestParseFlagsIsolatedPreservesPreviouslyParsedState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "empty"},
		{name: "explicit false", args: []string{"--copy=false", "--name=", "new operand"}},
		{name: "error after valid flag", args: []string{"--name=temporary", "--unknown"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "isolated-test"}
			var copyValue bool
			var nameValue string
			fs := cmd.Flags()
			fs.BoolVarP(&copyValue, "copy", "c", false, "copy")
			fs.StringVarP(&nameValue, "name", "n", "", "name")
			if err := fs.Parse([]string{"-c", "-n", "prior", "original operand"}); err != nil {
				t.Fatalf("seed flags: %v", err)
			}
			parsed, args, states := snapshotFlagSet(fs)
			t.Run("isolated parse", func(t *testing.T) {
				err := parseFlagsIsolated(t, cmd, tc.args)
				if (err != nil) != tc.wantErr {
					t.Fatalf("parse error = %v, want error %v", err, tc.wantErr)
				}
				if tc.name == "explicit false" && (copyValue || nameValue != "") {
					t.Fatalf("explicit zero values not applied: copy=%v name=%q", copyValue, nameValue)
				}
			})
			afterParsed, afterArgs, afterStates := snapshotFlagSet(fs)
			if parsed != afterParsed || !reflect.DeepEqual(args, afterArgs) || !reflect.DeepEqual(states, afterStates) {
				t.Errorf("shared flag state changed: parsed=%v args=%v states=%v; want parsed=%v args=%v states=%v",
					afterParsed, afterArgs, afterStates, parsed, args, states)
			}
		})
	}
}

func TestGetPrintsPasswordOnlyToTerminalOrWithReveal(t *testing.T) {
	cases := []struct {
		name            string
		reveal, term    bool
		copy, wantPrint bool
		wantRevealError bool
	}{
		{name: "non-terminal without reveal", wantRevealError: true},
		{name: "non-terminal with reveal", reveal: true, wantPrint: true},
		{name: "terminal without reveal", term: true, wantPrint: true},
		{name: "terminal with reveal", reveal: true, term: true, wantPrint: true},
		{name: "copy non-terminal", copy: true},
		{name: "copy with reveal", copy: true, reveal: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubRevealEnv(t, tc.reveal, tc.term)
			content := fakeClipboard(t, nil, nil)
			stubGetClearer(t, time.Second, func(string, time.Duration) error { return nil })

			var err error
			out := captureStdout(t, func() {
				err = handleGetOutput("github", map[string]string{"github": "s3cr3t"}, tc.copy)
			})
			if tc.wantRevealError != errors.Is(err, errRevealRequired) {
				t.Fatalf("reveal error mismatch: got %v", err)
			}
			if !tc.wantRevealError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "s3cr3t") {
				t.Fatalf("error leaks the secret: %v", err)
			}
			if got := strings.Contains(out, "s3cr3t"); got != tc.wantPrint {
				t.Fatalf("password printed=%v, want %v (stdout %q)", got, tc.wantPrint, out)
			}
			if tc.copy != (*content == "s3cr3t") || (tc.copy && out != "") {
				t.Fatalf("copy=%v: clipboard holds %q, stdout %q", tc.copy, *content, out)
			}
		})
	}
}

func TestGetRevealWarnsWithoutLeakingSecretToStderr(t *testing.T) {
	stubRevealEnv(t, true, false)
	var diagnostic string
	out := captureStdout(t, func() {
		diagnostic = captureGetStderr(t, func() {
			if err := handleGetOutput("account", map[string]string{"account": "test-secret"}, false); err != nil {
				t.Fatal(err)
			}
		})
	})
	if out != "account:test-secret" {
		t.Fatalf("unexpected reveal output %q", out)
	}
	if !strings.Contains(diagnostic, "Warning:") || !strings.Contains(diagnostic, "plaintext") {
		t.Fatalf("missing plaintext warning: %q", diagnostic)
	}
	if strings.Contains(diagnostic, "test-secret") {
		t.Fatalf("stderr must not contain the password: %q", diagnostic)
	}
}

// An empty-valued entry is present, not a failed lookup; empty stores and
// missing names fail without output, clipboard writes or leaked secrets.
func TestHandleGetOutputLookup(t *testing.T) {
	stubRevealEnv(t, true, false)
	oldWrite := clipboardWriteAll
	t.Cleanup(func() { clipboardWriteAll = oldWrite })
	clipboardWriteAll = func(string) error {
		t.Fatalf("clipboard must not be touched when the lookup fails")
		return nil
	}

	const emptyMsg = "get password 'github': the password store is empty; add one with 'pwd-manager add'"
	for _, tc := range []struct {
		name, key string
		saved     map[string]string
		copy      bool
		wantErr   error
		wantMsg   string
		wantOut   string
	}{
		{name: "nil store", key: "github", wantErr: errEmptyPasswordStore, wantMsg: emptyMsg},
		{name: "empty store copy", key: "github", saved: map[string]string{}, copy: true, wantErr: errEmptyPasswordStore, wantMsg: emptyMsg},
		{name: "missing key", key: "gitlab", saved: map[string]string{"github": "s3cr3t"}, wantErr: errPasswordNotFound, wantMsg: "get password 'gitlab': password not found"},
		{name: "missing key copy", key: "gitlab", saved: map[string]string{"github": "s3cr3t"}, copy: true, wantErr: errPasswordNotFound, wantMsg: "get password 'gitlab': password not found"},
		{name: "only other empty entry", key: "missing", saved: map[string]string{"other": ""}, wantErr: errPasswordNotFound, wantMsg: "get password 'missing': password not found"},
		{name: "existing empty key and value", key: "", saved: map[string]string{"": ""}, wantOut: ":"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() {
				err = handleGetOutput(tc.key, tc.saved, tc.copy)
			})
			if !errors.Is(err, tc.wantErr) || (err != nil && err.Error() != tc.wantMsg) {
				t.Fatalf("expected %v with message %q, got %v", tc.wantErr, tc.wantMsg, err)
			}
			if out != tc.wantOut {
				t.Fatalf("stdout = %q, want %q", out, tc.wantOut)
			}
		})
	}
}

func TestCopyPasswordToClipboard(t *testing.T) {
	content := fakeClipboard(t, nil, nil)
	out := captureStdout(t, func() {
		if err := copyPasswordToClipboard("new-pass-123"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
	if *content != "new-pass-123" {
		t.Fatalf("expected 'new-pass-123' written to clipboard, got %q", *content)
	}
	if out != "" {
		t.Fatalf("expected no output on success, got %q", out)
	}
}

func TestHandleGetOutputCopyError(t *testing.T) {
	oldWrite := clipboardWriteAll
	defer func() { clipboardWriteAll = oldWrite }()
	clipErr := errors.New("clipboard unavailable")
	clipboardWriteAll = func(string) error { return clipErr }

	var gotErr error
	out := captureStdout(t, func() {
		gotErr = handleGetOutput("github", map[string]string{"github": "s3cr3t"}, true)
	})

	const wantMsg = "failed to copy password to clipboard: clipboard unavailable"
	if !errors.Is(gotErr, clipErr) || !strings.Contains(gotErr.Error(), wantMsg) {
		t.Fatalf("expected error wrapping %v, got %v", clipErr, gotErr)
	}
	if !strings.Contains(out, wantMsg) {
		t.Fatalf("expected clear error message, got %q", out)
	}
	if strings.Contains(out, "s3cr3t") {
		t.Fatalf("expected secret not to be printed to stdout on error, got %q", out)
	}
}

func TestGetCopyClearsPasswordAfterConfiguredDelay(t *testing.T) {
	content := fakeClipboard(t, nil, nil)
	var gotDelay time.Duration
	stubGetClearer(t, 3*time.Second, func(pwd string, d time.Duration) error {
		gotDelay = d
		if *content != pwd {
			t.Fatalf("clear must run after copy, clipboard=%q", *content)
		}
		return verifyAndClearClipboard(pwd)
	})

	err := handleGetOutput("github", map[string]string{"github": "s3cr3t"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotDelay != 3*time.Second {
		t.Fatalf("expected configured delay 3s, got %v", gotDelay)
	}
	if *content != "" {
		t.Fatalf("expected clipboard cleared after get --copy, still holds %q", *content)
	}
}

func TestGetCopyLeavesClipboardChangedByUser(t *testing.T) {
	content := fakeClipboard(t, nil, nil)
	stubGetClearer(t, time.Second, func(pwd string, _ time.Duration) error {
		*content = "user copied this"
		return verifyAndClearClipboard(pwd)
	})

	if err := handleGetOutput("github", map[string]string{"github": "s3cr3t"}, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *content != "user copied this" {
		t.Fatalf("expected clipboard left alone, got %q", *content)
	}
}

func TestGetCopyRejectsNonPositiveDelayBeforeCopy(t *testing.T) {
	content := fakeClipboard(t, nil, nil)
	stubGetClearer(t, 0, func(string, time.Duration) error {
		t.Fatalf("clearer must not run for an invalid delay")
		return nil
	})

	err := handleGetOutput("github", map[string]string{"github": "s3cr3t"}, true)
	if !errors.Is(err, errInvalidClearAfter) {
		t.Fatalf("expected errInvalidClearAfter, got %v", err)
	}
	if *content != "" {
		t.Fatalf("expected nothing copied, clipboard holds %q", *content)
	}
}

func TestGetCopyReportsClearFailure(t *testing.T) {
	fakeClipboard(t, nil, nil)
	clearErr := errors.New("clear failed")
	stubGetClearer(t, time.Second, func(string, time.Duration) error { return clearErr })

	err := handleGetOutput("github", map[string]string{"github": "s3cr3t"}, true)
	if !errors.Is(err, clearErr) || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("expected wrapped clear error without secret, got %v", err)
	}
}

func TestGetClipboardClearAnnouncesDelayAndActuallyExpires(t *testing.T) {
	content := fakeClipboard(t, nil, nil)
	*content = "test-secret"
	// An already-due timer exercises the timer branch without sleeps or signals.
	diagnostic := captureGetStderr(t, func() {
		if err := clearCopiedPasswordAfter("test-secret", time.Nanosecond); err != nil {
			t.Fatal(err)
		}
	})
	if *content != "" {
		t.Fatal("expired clipboard entry was not cleared")
	}
	if !strings.Contains(diagnostic, "1ns") || !strings.Contains(diagnostic, "cleared") {
		t.Fatalf("missing configured expiry diagnostic: %q", diagnostic)
	}
	if strings.Contains(diagnostic, "test-secret") {
		t.Fatalf("expiry diagnostic contains password: %q", diagnostic)
	}
}
