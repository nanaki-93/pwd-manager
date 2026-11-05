package cmd

import (
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

// A wrong current password must end the command with a non-zero exit status,
// not just print a message, so scripts can detect the failed verification.
func TestSavePasswordWrongCurrentPasswordExitsNonZero(t *testing.T) {
	withTempHome(t)
	exitCount := captureExit(t)
	prompts := 0
	restorePrompt := setUtilsReadPassword(func() ([]byte, error) {
		prompts++
		return []byte("wrong-current-password"), nil
	})
	t.Cleanup(restorePrompt)

	output := captureStdout(t, func() {
		savePassword(model.PwdFile{MasterPassword: "existing-master"})
	})

	if *exitCount != 1 {
		t.Fatalf("expected one non-zero exit for a wrong current password, got %d", *exitCount)
	}
	if prompts != 1 {
		t.Fatalf("expected only the current-password prompt, got %d prompts", prompts)
	}
	if !strings.Contains(output, "Passwords do not match") {
		t.Fatalf("expected 'Passwords do not match' in output, got %q", output)
	}
	if strings.Contains(output, "Password saved") {
		t.Fatalf("did not expect 'Password saved' in output, got %q", output)
	}
}
