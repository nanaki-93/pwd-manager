package model

import "testing"

func TestNewPwdFileInitializesMap(t *testing.T) {
	pf := NewPwdFile("secret")
	if pf == nil {
		t.Fatal("NewPwdFile returned nil")
	}
	if pf.MasterPassword != "secret" {
		t.Fatalf("MasterPassword = %q, want %q", pf.MasterPassword, "secret")
	}
	if pf.SavedPasswords == nil {
		t.Fatal("SavedPasswords is nil")
	}
	if len(pf.SavedPasswords) != 0 {
		t.Fatalf("SavedPasswords has %d entries, want 0", len(pf.SavedPasswords))
	}
	pf.SavedPasswords["site"] = "pw"
	if got := pf.SavedPasswords["site"]; got != "pw" {
		t.Fatalf("SavedPasswords[site] = %q, want %q", got, "pw")
	}
}
