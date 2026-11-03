package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

func TestCopyFlagParsingRestoresNonDefaultCopyValues(t *testing.T) {
	oldGet, oldAdd, oldName := getCopyFlag, addCopyFlag, nameFlag
	t.Cleanup(func() {
		getCopyFlag, addCopyFlag, nameFlag = oldGet, oldAdd, oldName
	})
	getCopyFlag, addCopyFlag, nameFlag = true, true, "existing name"

	for i := 0; i < 2; i++ {
		t.Run("parse", TestGetAndAddCopyFlagParsing)
		if !getCopyFlag || !addCopyFlag || nameFlag != "existing name" {
			t.Fatalf("iteration %d did not restore prior values: get=%v add=%v name=%q",
				i, getCopyFlag, addCopyFlag, nameFlag)
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
