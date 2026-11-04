package model_test

import (
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

// These assignments pin the public constructor and existing field types.
var _ func(string) *model.PwdFile = model.NewPwdFile
var _ *string = &new(model.PwdFile).MasterPassword
var _ *map[string]string = &new(model.PwdFile).SavedPasswords

func TestNewPwdFilePreservesBoundaryMasters(t *testing.T) {
	for _, master := range []string{"", " \t\n", "日本語\x00master"} {
		t.Run(master, func(t *testing.T) {
			p := model.NewPwdFile(master)
			if p == nil {
				t.Fatal("NewPwdFile returned nil")
			}
			if p.MasterPassword != master {
				t.Fatal("constructor changed master password")
			}
			if p.SavedPasswords == nil || len(p.SavedPasswords) != 0 {
				t.Fatal("expected an initialized empty map")
			}
			p.SavedPasswords[""] = ""
			if _, ok := p.SavedPasswords[""]; !ok {
				t.Fatal("empty key/value entry was not retained")
			}
		})
	}
}

func TestNewPwdFileInstancesAreIndependent(t *testing.T) {
	first := model.NewPwdFile("master")
	second := model.NewPwdFile("master")
	if first == nil || second == nil {
		t.Fatal("NewPwdFile returned nil")
	}
	if first.SavedPasswords == nil || second.SavedPasswords == nil {
		t.Fatal("NewPwdFile returned a nil map")
	}
	first.SavedPasswords["site"] = "first"
	if _, ok := second.SavedPasswords["site"]; ok {
		t.Fatal("constructors share saved passwords")
	}
	second.SavedPasswords["site"] = "second"
	if first.SavedPasswords["site"] != "first" {
		t.Fatal("mutating second instance changed first instance")
	}
}
