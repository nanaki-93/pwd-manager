package daemon

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

var (
	errEmptyNewPassword = errors.New("new password cannot be empty")
	errPasswordMismatch = errors.New("passwords do not match")
	errEmptyPwdName     = errors.New("password name cannot be empty")
	errVaultLocked      = errors.New("password store is locked")
	errPasswordNotFound = errors.New("password not found")
	errPasswordExists   = errors.New("password already exists; edit it instead")
)

// storeOps are the store and clipboard operations a storeVault uses.
type storeOps struct {
	unlockBiometric func() (model.PwdFile, error)
	unlockMaster    func(master []byte) (model.PwdFile, error)
	save            func(model.PwdFile, error) error
	copy            func(pwd string) error
}

// storeVault implements ui.Vault over the encrypted password store. It holds
// the decrypted store only between an unlock and Lock.
type storeVault struct {
	ops   storeOps
	mu    sync.Mutex
	store *model.PwdFile
}

// newStoreVault returns a locked vault over the store in the home directory;
// copies go through copyPasswordToClipboard and its auto-clear.
func newStoreVault() *storeVault {
	return &storeVault{ops: storeOps{
		unlockBiometric: utils.UnlockStoreBiometric,
		unlockMaster:    utils.UnlockStore,
		save:            utils.SaveFileErr,
		copy:            copyPasswordToClipboard,
	}}
}

// UnlockBiometric unlocks with Touch ID and reports false, without an error,
// when Touch ID is unavailable so the caller asks for the master password.
func (v *storeVault) UnlockBiometric() (bool, error) {
	pwdObj, err := v.ops.unlockBiometric()
	if errors.Is(err, utils.ErrBiometricUnavailable) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("unlock with touch id: %w", err)
	}
	v.setStore(pwdObj)
	return true, nil
}

// Unlock unlocks the store with the master password.
func (v *storeVault) Unlock(master []byte) error {
	pwdObj, err := v.ops.unlockMaster(master)
	if err != nil {
		return fmt.Errorf("unlock with master password: %w", err)
	}
	v.setStore(pwdObj)
	return nil
}

func (v *storeVault) setStore(pwdObj model.PwdFile) {
	if pwdObj.SavedPasswords == nil {
		pwdObj.SavedPasswords = make(map[string]string)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.store = &pwdObj
}

// Lock drops the decrypted store.
func (v *storeVault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.store = nil
}

// Names returns the saved names in ascending order, or none while locked.
func (v *storeVault) Names() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.store == nil {
		return nil
	}
	return sortedPasswordNames(v.store.SavedPasswords)
}

// Copy copies the password saved under name to the clipboard.
func (v *storeVault) Copy(name string) error {
	v.mu.Lock()
	pwd, err := v.lookupLocked(name)
	v.mu.Unlock()
	if err != nil {
		return fmt.Errorf("copy password: %w", err)
	}
	if err := v.ops.copy(pwd); err != nil {
		return fmt.Errorf("copy password %q: %w", name, err)
	}
	return nil
}

// Update replaces the password saved under name with pwd once confirm
// matches it; see updateSavedPassword.
func (v *storeVault) Update(name, pwd, confirm string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := v.lookupLocked(name); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return updateSavedPassword(*v.store, name, pwd, confirm, v.ops.save)
}

// Add saves pwd under a new, valid name; an existing name is refused so a
// password is only replaced through Update.
func (v *storeVault) Add(name, pwd string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("add password: %w", errEmptyPwdName)
	}
	if err := model.ValidatePwdName(name); err != nil {
		return fmt.Errorf("add password: %w", err)
	}
	if pwd == "" {
		return fmt.Errorf("add password %q: %w", name, errEmptyNewPassword)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.store == nil {
		return fmt.Errorf("add password %q: %w", name, errVaultLocked)
	}
	if _, exists := v.store.SavedPasswords[name]; exists {
		return fmt.Errorf("add password %q: %w", name, errPasswordExists)
	}
	v.store.SavedPasswords[name] = pwd
	if err := v.ops.save(*v.store, nil); err != nil {
		delete(v.store.SavedPasswords, name)
		return fmt.Errorf("save password %q: %w", name, err)
	}
	return nil
}

// Remove deletes the password saved under name; a failed save restores it.
func (v *storeVault) Remove(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	prev, err := v.lookupLocked(name)
	if err != nil {
		return fmt.Errorf("remove password: %w", err)
	}
	delete(v.store.SavedPasswords, name)
	if err := v.ops.save(*v.store, nil); err != nil {
		v.store.SavedPasswords[name] = prev
		return fmt.Errorf("persist password removal for %q: %w", name, err)
	}
	return nil
}

// lookupLocked returns the password saved under name. The caller holds v.mu.
func (v *storeVault) lookupLocked(name string) (string, error) {
	if v.store == nil {
		return "", errVaultLocked
	}
	pwd, ok := v.store.SavedPasswords[name]
	if !ok {
		return "", fmt.Errorf("%q: %w", name, errPasswordNotFound)
	}
	return pwd, nil
}

// updateSavedPassword saves newPwd as the entry name with save. An empty
// value or a mismatched confirmation leaves the store untouched; a failed
// save restores the entry.
func updateSavedPassword(pwdObj model.PwdFile, name, newPwd, confirm string, save func(model.PwdFile, error) error) error {
	if newPwd == "" {
		return fmt.Errorf("update password %q: %w", name, errEmptyNewPassword)
	}
	if subtle.ConstantTimeCompare([]byte(newPwd), []byte(confirm)) != 1 {
		return fmt.Errorf("update password %q: %w", name, errPasswordMismatch)
	}

	prev := pwdObj.SavedPasswords[name]
	pwdObj.SavedPasswords[name] = newPwd
	if err := save(pwdObj, nil); err != nil {
		pwdObj.SavedPasswords[name] = prev
		return fmt.Errorf("save password %q: %w", name, err)
	}
	return nil
}
