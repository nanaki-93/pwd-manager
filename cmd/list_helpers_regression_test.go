package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type resetRejectingValue struct {
	err error
}

func (v *resetRejectingValue) String() string { return "current" }
func (v *resetRejectingValue) Type() string   { return "reset-rejecting" }
func (v *resetRejectingValue) Set(string) error {
	return v.err
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
