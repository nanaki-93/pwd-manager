package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

func TestReadPwdNameWithSpaces(t *testing.T) {
	name, err := readPwdName(strings.NewReader("my email account\n"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if name != "my email account" {
		t.Fatalf("expected %q, got %q", "my email account", name)
	}
}

func TestReadPwdNameTrimsSurroundingWhitespaceAndHandlesEOF(t *testing.T) {
	name, err := readPwdName(strings.NewReader("  work vpn account  "))
	if err != nil {
		t.Fatalf("expected no error on unterminated non-empty line, got %v", err)
	}
	if name != "work vpn account" {
		t.Fatalf("expected %q, got %q", "work vpn account", name)
	}
}

func TestReadPwdNameEmpty(t *testing.T) {
	_, err := readPwdName(strings.NewReader("   \n"))
	if err == nil {
		t.Fatal("expected error for empty password name, got nil")
	}

	_, err = readPwdName(strings.NewReader(""))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF for empty reader, got %v", err)
	}
}

func TestCanSavePasswordExistingKey(t *testing.T) {
	saved := map[string]string{"github": "secret"}

	proceed, err := canSavePassword(saved, "github", strings.NewReader("n\n"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if proceed {
		t.Fatal("expected proceed to be false when user declines overwrite")
	}

	proceed, err = canSavePassword(saved, "github", strings.NewReader("y\n"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !proceed {
		t.Fatal("expected proceed to be true when user confirms overwrite")
	}

	proceed, err = canSavePassword(saved, "github", strings.NewReader("  Y \n"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !proceed {
		t.Fatal("expected proceed to be true when user confirms overwrite with uppercase Y")
	}

	proceed, err = canSavePassword(saved, "github", strings.NewReader("\n"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if proceed {
		t.Fatal("expected proceed to be false on empty confirmation input")
	}

	proceed, err = canSavePassword(saved, "gitlab", strings.NewReader(""))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !proceed {
		t.Fatal("expected proceed to be true when key does not exist")
	}

	proceed, err = canSavePassword(nil, "github", strings.NewReader(""))
	if err != nil {
		t.Fatalf("expected no error with nil map, got %v", err)
	}
	if !proceed {
		t.Fatal("expected proceed to be true when map is nil")
	}
}

func TestSavePasswordRejectsEmptyCurrentPassword(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	// In non-terminal test environments, term.ReadPassword fails immediately and returns empty bytes,
	// simulating an empty current password input.
	savePassword(model.PwdFile{MasterPassword: "existing-master"})

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()

	output := buf.String()
	if !strings.Contains(output, "Passwords do not match") {
		t.Fatalf("expected 'Passwords do not match' in output, got %q", output)
	}
	if strings.Contains(output, "Password saved") {
		t.Fatalf("did not expect 'Password saved' in output, got %q", output)
	}
}

func TestSavePasswordWhenMasterPasswordEmpty(t *testing.T) {
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	generateKey()
	savePassword(model.PwdFile{MasterPassword: ""})

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()

	output := buf.String()
	if strings.Contains(output, "Enter your current password:") {
		t.Fatalf("did not expect current password prompt when MasterPassword is empty, got %q", output)
	}
	if !strings.Contains(output, "Enter your new password:") {
		t.Fatalf("expected new password prompt when MasterPassword is empty, got %q", output)
	}
	if !strings.Contains(output, "Password saved") {
		t.Fatalf("expected 'Password saved' in output, got %q", output)
	}
}
