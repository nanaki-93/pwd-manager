package cmd

import (
	"errors"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func TestStorePasswordValueBoundaries(t *testing.T) {
	orig := saveVault
	t.Cleanup(func() { saveVault = orig })

	for _, value := range []string{"", " ", "\t\n", "x", "\x00", "🔐"} {
		t.Run("value="+value, func(t *testing.T) {
			calls := 0
			var saved model.PwdFile
			saveVault = func(p model.PwdFile, in error) error {
				if in != nil {
					t.Fatalf("unexpected incoming error: %v", in)
				}
				calls++
				saved = p
				return nil
			}
			err := storePassword(model.PwdFile{}, "new-entry", value)
			if value == "" {
				if !errors.Is(err, errEmptyPassword) || calls != 0 {
					t.Fatalf("empty value: error=%v, save calls=%d; want rejection without persistence", err, calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("nonempty value rejected: %v", err)
			}
			if calls != 1 || saved.SavedPasswords["new-entry"] != value {
				t.Fatalf("expected one save preserving the exact nonempty value; calls=%d", calls)
			}
		})
	}
}

func TestExecAddCmdWithoutCopyDoesNotAccessClipboard(t *testing.T) {
	seedExecAddVault(t, "valid-master-pass", map[string]string{"existing": "keep"})
	origClip, origCopy := clipboardWriteAll, addCopyFlag
	t.Cleanup(func() {
		clipboardWriteAll = origClip
		addCopyFlag = origCopy
	})
	calls := 0
	clipboardWriteAll = func(string) error {
		calls++
		return errors.New("clipboard must not be accessed")
	}
	addCopyFlag = false
	stubPasswordSequence(t, "valid-master-pass", "no-copy-secret")
	exits := captureExit(t)
	captureStdout(t, func() {
		feedStdinInput(t, "github\n", func() {
			execAddCmd(addCmd, nil)
		})
	})
	if calls != 0 || *exits != 0 {
		t.Fatalf("without --copy: clipboard calls=%d, exits=%d; want neither", calls, *exits)
	}
	utils.SetMasterKey([]byte("valid-master-pass"))
	loaded, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("reload saved vault: %v", err)
	}
	if loaded.SavedPasswords["github"] != "no-copy-secret" || loaded.SavedPasswords["existing"] != "keep" {
		t.Fatal("add without --copy must persist the new value and preserve existing entries")
	}
}
