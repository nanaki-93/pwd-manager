package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

// A store that holds entries but has an empty master hash must not be treated
// as initialization: the master command refuses to rotate its key.
func TestExecMasterCmdRefusesExistingStoreWithEmptyHash(t *testing.T) {
	tmpHome := withTempHome(t)
	utils.SetMasterKey([]byte("original-secret"))
	fixture := model.PwdFile{SavedPasswords: map[string]string{"bank": "hunter22"}}
	if err := utils.SaveFileErr(fixture, nil); err != nil {
		t.Fatalf("write fixture store: %v", err)
	}
	pwdPath := filepath.Join(tmpHome, utils.PwdFileName)
	before, err := os.ReadFile(pwdPath)
	if err != nil {
		t.Fatalf("read fixture store: %v", err)
	}
	stubPasswordSequence(t, "attacker-chosen-secret")
	exitCount := captureExit(t)

	output := captureStdout(t, func() {
		feedStdinInput(t, "y\n", func() { execMasterCmd(masterCmd, nil) })
	})

	if *exitCount == 0 || !strings.Contains(output, errMissingMasterHash.Error()) {
		t.Fatalf("expected missing-hash error and exit, got %d exits, output %q", *exitCount, output)
	}
	if strings.Contains(output, "Enter your new password:") {
		t.Fatalf("did not expect a new password prompt, got %q", output)
	}
	after, err := os.ReadFile(pwdPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("store was rewritten despite missing master hash (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(tmpHome, keyDerivationSaltFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no salt file written, got stat err: %v", err)
	}
}

func TestRequireMasterHash(t *testing.T) {
	withEntries := model.PwdFile{SavedPasswords: map[string]string{"a": "b"}}
	cases := []struct {
		name    string
		content model.PwdFile
		exists  bool
		wantErr bool
	}{
		{"fresh init", model.PwdFile{}, false, false},
		{"existing store empty hash", model.PwdFile{}, true, true},
		{"entries without hash", withEntries, false, true},
		{"hash present", model.PwdFile{MasterPassword: "pbkdf2-sha256$x"}, true, false},
	}
	for _, tc := range cases {
		err := requireMasterHash(tc.content, tc.exists)
		if (err != nil) != tc.wantErr || (err != nil && !errors.Is(err, errMissingMasterHash)) {
			t.Fatalf("%s: requireMasterHash = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestSavePasswordRefusesEntriesWithoutHash(t *testing.T) {
	_ = withTempHome(t)
	stubPasswordSequence(t, "attacker-chosen-secret")
	exitCount := captureExit(t)
	output := captureStdout(t, func() {
		savePassword(model.PwdFile{SavedPasswords: map[string]string{"bank": "hunter22"}})
	})
	if *exitCount == 0 || strings.Contains(output, "Password saved") {
		t.Fatalf("expected refusal for entries without a master hash, got %d exits, output %q", *exitCount, output)
	}
}
