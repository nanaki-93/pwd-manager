package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func TestRotationPersistsSaltAndRetainsLegacyKeyBeforeSave(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			home := withTempHome(t)
			legacy := bytes.Repeat([]byte{0x42}, 32)
			seedLegacyVault(t, home, legacy, model.PwdFile{MasterPassword: "old-hash"})
			stubFixedRandSalt(t, 0x68, nil)
			saveErr := errors.New("injected save failure")
			originalSave := saveStore
			t.Cleanup(func() { saveStore = originalSave })
			calls := 0
			saveStore = func(content model.PwdFile, upstream error) error {
				calls++
				if content.MasterPassword != "new-hash" || upstream != nil {
					t.Fatal("save did not receive the new hash")
				}
				got, err := os.ReadFile(filepath.Join(home, utils.PwdFileKey))
				if err != nil || !bytes.Equal(got, legacy) {
					t.Fatalf("legacy key removed before save: %v", err)
				}
				iterations, salt := readStoredSaltParams(t, home)
				if iterations < minAcceptedKDFIterations || !bytes.Equal(salt, bytes.Repeat([]byte{0x68}, 32)) {
					t.Fatal("new salt and parameters were not persisted before save")
				}
				if fail {
					return saveErr
				}
				return originalSave(content, upstream)
			}
			err := rotateMasterKey([]byte("valid-master-secret"), model.PwdFile{MasterPassword: "new-hash"})
			if calls != 1 {
				t.Fatalf("save calls = %d, want 1", calls)
			}
			if fail {
				if !errors.Is(err, saveErr) || !strings.Contains(err.Error(), "save store with new master key:") {
					t.Fatalf("missing wrapped save context: %v", err)
				}
			} else if err != nil {
				t.Fatalf("rotation failed: %v", err)
			}
		})
	}
}

func TestRotationSaltFailureDoesNotCallSaveOrRemoveLegacyKey(t *testing.T) {
	home := withTempHome(t)
	legacy := bytes.Repeat([]byte{0x42}, 32)
	seedLegacyVault(t, home, legacy, model.PwdFile{})
	stubFixedRandSalt(t, 0x68, nil)
	originalRand := randRead
	randRead = func(r io.Reader, salt []byte) (int, error) {
		n, err := originalRand(r, salt)
		if mkdirErr := os.Mkdir(filepath.Join(home, keyDerivationSaltFile), 0o700); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		return n, err
	}
	originalSave := saveStore
	t.Cleanup(func() { saveStore = originalSave })
	saveStore = func(model.PwdFile, error) error {
		t.Fatal("save called despite salt persistence failure")
		return nil
	}
	err := rotateMasterKey([]byte("valid-master-secret"), model.PwdFile{})
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Op != "write" || pathErr.Path != keyDerivationSaltFile {
		t.Fatalf("missing salt write context: %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(home, utils.PwdFileKey))
	if readErr != nil || !bytes.Equal(got, legacy) {
		t.Fatalf("legacy key changed after salt failure: %v", readErr)
	}
}
