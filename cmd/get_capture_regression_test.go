package cmd

import (
	"testing"

	"github.com/spf13/pflag"
)

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

// TestGetAndAddCopyFlagParsingLeavesSharedFlagSetsUntouched guards against
// TestGetAndAddCopyFlagParsing leaking parse state into the package-level
// getCmd/addCmd flag sets or resetting nameFlag to "" instead of its prior value.
func TestGetAndAddCopyFlagParsingLeavesSharedFlagSetsUntouched(t *testing.T) {
	oldName := nameFlag
	nameFlag = "pre-existing"
	t.Cleanup(func() { nameFlag = oldName })

	type snap struct {
		parsed bool
		args   []string
		states map[string]flagState
	}
	take := func() map[string]snap {
		out := map[string]snap{}
		for name, fs := range map[string]*pflag.FlagSet{"get": getCmd.Flags(), "add": addCmd.Flags()} {
			p, a, s := snapshotFlagSet(fs)
			out[name] = snap{parsed: p, args: a, states: s}
		}
		return out
	}

	before := take()
	t.Run("inner", TestGetAndAddCopyFlagParsing)
	after := take()

	if nameFlag != "pre-existing" {
		t.Fatalf("nameFlag not restored to its prior value: got %q", nameFlag)
	}
	for cmdName, b := range before {
		a := after[cmdName]
		if a.parsed != b.parsed {
			t.Errorf("%s flag set Parsed() changed from %v to %v", cmdName, b.parsed, a.parsed)
		}
		if len(a.args) != len(b.args) {
			t.Errorf("%s flag set Args() changed from %v to %v", cmdName, b.args, a.args)
		}
		for flagName, bs := range b.states {
			if as := a.states[flagName]; as != bs {
				t.Errorf("%s --%s state changed from %+v to %+v", cmdName, flagName, bs, as)
			}
		}
	}
}
