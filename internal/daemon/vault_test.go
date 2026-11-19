package daemon

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func TestVaultUnlockBiometric(t *testing.T) {
	failure := errors.New("biometric failure")
	for _, tc := range []struct {
		name    string
		err     error
		want    bool
		wantErr error
	}{
		{"success", nil, true, nil},
		{"unavailable", utils.ErrBiometricUnavailable, false, nil},
		{"failure", failure, false, failure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &storeVault{ops: storeOps{unlockBiometric: func() (model.PwdFile, error) {
				return model.PwdFile{SavedPasswords: map[string]string{"site": "secret"}}, tc.err
			}}}
			got, err := v.UnlockBiometric()
			if got != tc.want || !errors.Is(err, tc.wantErr) || (len(v.Names()) > 0) != tc.want {
				t.Fatalf("unlock = %v, %v; names = %v", got, err, v.Names())
			}
		})
	}
}

func TestVaultMasterAndCRUD(t *testing.T) {
	failure := errors.New("wrong master")
	saves := 0
	v := &storeVault{ops: storeOps{
		unlockMaster: func(master []byte) (model.PwdFile, error) {
			if string(master) != "master" {
				return model.PwdFile{}, failure
			}
			return model.PwdFile{SavedPasswords: map[string]string{"z": "old", "a": "first"}}, nil
		},
		save: func(_ model.PwdFile, _ error) error { saves++; return nil },
	}}
	if err := v.Unlock([]byte("bad")); !errors.Is(err, failure) {
		t.Fatalf("unlock: %v", err)
	}
	for _, op := range []func() error{
		func() error { return v.Add("new", "pwd") },
		func() error { return v.Update("z", "pwd", "pwd") },
		func() error { return v.Remove("z") },
	} {
		if err := op(); !errors.Is(err, errVaultLocked) {
			t.Fatalf("locked operation: %v", err)
		}
	}
	if err := v.Unlock([]byte("master")); err != nil {
		t.Fatal(err)
	}
	if got := v.Names(); !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Fatalf("names: %v", got)
	}
	if err := v.Update("missing", "pwd", "pwd"); !errors.Is(err, errPasswordNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if err := v.Remove("missing"); !errors.Is(err, errPasswordNotFound) {
		t.Fatalf("remove missing: %v", err)
	}
	if err := v.Add(" b ", "new"); err != nil {
		t.Fatal(err)
	}
	if err := v.Update("z", "changed", "changed"); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove("a"); err != nil {
		t.Fatal(err)
	}
	if got := v.Names(); !reflect.DeepEqual(got, []string{"b", "z"}) || v.store.SavedPasswords["z"] != "changed" || saves != 3 {
		t.Fatalf("names=%v store=%v saves=%d", got, v.store.SavedPasswords, saves)
	}
}

func TestVaultAddValidationAndRollback(t *testing.T) {
	saveErr := errors.New("save failed")
	saves := 0
	v := &storeVault{ops: storeOps{save: func(model.PwdFile, error) error {
		saves++
		return saveErr
	}}}
	v.setStore(model.PwdFile{SavedPasswords: map[string]string{"site": "old"}})
	for _, tc := range []struct {
		name, pwd string
		want      error
	}{
		{" ", "secret", errEmptyPwdName},
		{"bad\nname", "secret", model.ErrInvalidPwdName},
		{strings.Repeat("é", model.MaxPwdNameLen+1), "secret", model.ErrInvalidPwdName},
		{"site", "secret", errPasswordExists},
		{"new", "", errEmptyNewPassword},
	} {
		if err := v.Add(tc.name, tc.pwd); !errors.Is(err, tc.want) {
			t.Errorf("Add(%q): %v, want %v", tc.name, err, tc.want)
		}
	}
	if saves != 0 {
		t.Fatalf("invalid additions caused %d saves", saves)
	}
	if err := v.Add(" new ", "secret"); !errors.Is(err, saveErr) {
		t.Fatalf("Add: %v", err)
	}
	if got := v.Names(); !reflect.DeepEqual(got, []string{"site"}) {
		t.Fatalf("names after failed save: %v", got)
	}
}

func TestVaultRemoveFailureAndLock(t *testing.T) {
	saveErr := errors.New("save failed")
	var copied string
	v := &storeVault{ops: storeOps{
		save: func(model.PwdFile, error) error { return saveErr },
		copy: func(pwd string) error { copied = pwd; return nil },
	}}
	v.setStore(model.PwdFile{SavedPasswords: map[string]string{"site": "old"}})
	if err := v.Remove("site"); !errors.Is(err, saveErr) {
		t.Fatalf("Remove: %v", err)
	}
	if err := v.Copy("site"); err != nil || copied != "old" {
		t.Fatalf("copy after failed removal: %q, %v", copied, err)
	}
	v.Lock()
	if len(v.Names()) != 0 {
		t.Fatal("locked vault exposes names")
	}
	if err := v.Copy("site"); !errors.Is(err, errVaultLocked) {
		t.Fatalf("copy while locked: %v", err)
	}
}
