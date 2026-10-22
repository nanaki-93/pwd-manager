package cmd

import (
	"bufio"
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

func TestSharedBufferedReaderSequentialPrompts(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantName    string
		wantProceed bool
	}{
		{
			name:        "confirms overwrite on second line",
			input:       "github\ny\n",
			wantName:    "github",
			wantProceed: true,
		},
		{
			name:        "confirms overwrite without trailing newline",
			input:       "github\ny",
			wantName:    "github",
			wantProceed: true,
		},
		{
			name:        "declines overwrite on second line",
			input:       "github\nn\n",
			wantName:    "github",
			wantProceed: false,
		},
		{
			name:        "eof on second prompt defaults to false",
			input:       "github\n",
			wantName:    "github",
			wantProceed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create stdin pipe: %v", err)
			}
			defer func() {
				_ = r.Close()
			}()

			if _, err := io.WriteString(w, tc.input); err != nil {
				_ = w.Close()
				t.Fatalf("failed to write piped input: %v", err)
			}
			_ = w.Close()

			oldStdin := os.Stdin
			os.Stdin = r
			defer func() {
				os.Stdin = oldStdin
			}()

			stdinReader := bufio.NewReader(os.Stdin)

			name, err := readPwdName(stdinReader)
			if err != nil {
				t.Fatalf("expected no error reading password name, got %v", err)
			}
			if name != tc.wantName {
				t.Fatalf("expected password name %q, got %q", tc.wantName, name)
			}

			saved := map[string]string{"github": "secret"}
			proceed, err := canSavePassword(saved, name, stdinReader)
			if err != nil {
				t.Fatalf("expected no error reading overwrite confirmation, got %v", err)
			}
			if proceed != tc.wantProceed {
				t.Fatalf("expected proceed=%v, got %v", tc.wantProceed, proceed)
			}
		})
	}
}

type failingReader struct {
	err error
}

func (f failingReader) Read(_ []byte) (int, error) {
	return 0, f.err
}

func TestPromptReadersPropagateReadErrors(t *testing.T) {
	readErr := errors.New("stdin read error")

	_, err := readPwdName(failingReader{err: readErr})
	if !errors.Is(err, readErr) {
		t.Fatalf("expected error %v from readPwdName, got %v", readErr, err)
	}

	saved := map[string]string{"github": "secret"}
	proceed, err := canSavePassword(saved, "github", failingReader{err: readErr})
	if !errors.Is(err, readErr) {
		t.Fatalf("expected error %v from canSavePassword, got %v", readErr, err)
	}
	if proceed {
		t.Fatal("expected proceed to be false on read error")
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
