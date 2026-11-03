package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func TestExecMasterCmdTreatsEmptyConfirmationAsDecline(t *testing.T) {
	_ = withTempHome(t)
	stubPasswordSequence(t, "initial-secret")
	execMasterCmd(masterCmd, nil)
	initial, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("initial setup: %v", err)
	}

	for _, input := range []string{"\n", "  \n", "\r\n", ""} {
		exitCount := captureExit(t)
		feedStdinInput(t, input, func() { execMasterCmd(masterCmd, nil) })
		if *exitCount != 0 {
			t.Fatalf("confirmation %q aborted with %d exits, want a decline", input, *exitCount)
		}
		loaded, err := utils.GetPwdObj()
		if err != nil || loaded.MasterPassword != initial.MasterPassword {
			t.Fatalf("confirmation %q changed the master password (err=%v)", input, err)
		}
	}
}

type errConfirmReader struct{ err error }

func (f errConfirmReader) Read([]byte) (int, error) { return 0, f.err }

func TestReadConfirmation(t *testing.T) {
	cases := map[string]string{"y\n": "y", "\n": "", "": "", "yes": "yes", "n\nrest\n": "n"}
	for input, want := range cases {
		got, err := readConfirmation(strings.NewReader(input))
		if err != nil || got != want {
			t.Fatalf("readConfirmation(%q) = (%q, %v), want (%q, nil)", input, got, err, want)
		}
	}
	readErr := errors.New("device gone")
	if _, err := readConfirmation(errConfirmReader{readErr}); !errors.Is(err, readErr) {
		t.Fatalf("readConfirmation read error = %v, want wrapped %v", err, readErr)
	}
}
