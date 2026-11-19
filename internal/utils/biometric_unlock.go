package utils

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/nanaki-93/pwd-manager/internal/biometric"
	"github.com/nanaki-93/pwd-manager/internal/model"
)

// BiometricMarkerName is written beside the store while Touch ID unlock is
// enabled; without it the master password is always typed.
const BiometricMarkerName = ".pwd-mng-touchid"

const (
	unlockReason = "unlock your password store"
	enableReason = "enable Touch ID unlock for your password store"
)

// ErrBiometricUnavailable reports that Touch ID did not unlock the store
// (not enabled, unavailable, cancelled or a stale saved secret), so callers
// fall back to the typed master password.
var ErrBiometricUnavailable = errors.New("touch id unlock unavailable")

var errBiometricNotEnabled = fmt.Errorf("%w: not enabled", ErrBiometricUnavailable)

// biometrics is the Touch ID prompt and the Keychain storage of the master
// secret; tests pass fakes.
type biometrics struct {
	authenticate func(reason string) error
	loadSecret   func() ([]byte, error)
	saveSecret   func(secret []byte) error
	deleteSecret func() error
}

// systemBiometrics returns the real Touch ID and Keychain implementation.
func systemBiometrics() biometrics {
	return biometrics{
		authenticate: biometric.Authenticate,
		loadSecret:   biometric.LoadSecret,
		saveSecret:   biometric.SaveSecret,
		deleteSecret: biometric.DeleteSecret,
	}
}

// BiometricEnabled reports whether the Touch ID opt-in marker exists.
func BiometricEnabled() (bool, error) {
	markerPath, err := resolveHomePath(BiometricMarkerName)
	if err != nil {
		return false, err
	}
	_, err = lstatRegularFile(markerPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check touch id marker: %w", err)
	}
	return true, nil
}

// UnlockStoreBiometric unlocks the store with the master secret Touch ID
// releases from the Keychain. Any error matching ErrBiometricUnavailable means
// the caller should ask for the master password instead.
func UnlockStoreBiometric() (model.PwdFile, error) {
	if err := requireStoreFile(); err != nil {
		return model.PwdFile{}, fmt.Errorf("open password store: %w", err)
	}
	pwdObj, err := unlockBiometric(systemBiometrics())
	if err != nil {
		return model.PwdFile{}, fmt.Errorf("unlock password store: %w", err)
	}
	return pwdObj, nil
}

// unlockSecret unlocks the store with Touch ID when enabled and otherwise
// with the password prompt returns, telling notices why Touch ID was skipped
// unless it simply is not enabled.
func unlockSecret(bio biometrics, prompt func() []byte, notices io.Writer) (model.PwdFile, error) {
	pwdObj, err := unlockBiometric(bio)
	if !errors.Is(err, ErrBiometricUnavailable) {
		return pwdObj, err
	}
	if !errors.Is(err, errBiometricNotEnabled) {
		fmt.Fprintf(notices, "%v; enter your master password instead.\n", err)
	}
	pwd := prompt()
	// SetMasterKey keeps its own copy; the prompted buffer is wiped on return.
	defer wipeBytes(pwd)
	return unlockWithPassword(pwd)
}

// unlockBiometric unlocks with the Keychain secret after a Touch ID prompt.
// A secret that no longer unlocks the store is removed with the marker.
func unlockBiometric(bio biometrics) (model.PwdFile, error) {
	enabled, err := BiometricEnabled()
	if err != nil {
		return model.PwdFile{}, fmt.Errorf("%w: %w", ErrBiometricUnavailable, err)
	}
	if !enabled {
		return model.PwdFile{}, errBiometricNotEnabled
	}
	if err := bio.authenticate(unlockReason); err != nil {
		return model.PwdFile{}, fmt.Errorf("%w: %w", ErrBiometricUnavailable, err)
	}
	secret, err := bio.loadSecret()
	if err != nil {
		return model.PwdFile{}, fmt.Errorf("%w: %w", ErrBiometricUnavailable, err)
	}
	// SetMasterKey keeps its own copy; the Keychain buffer is wiped on return.
	defer wipeBytes(secret)
	pwdObj, err := unlockWithPassword(secret)
	if errors.Is(err, ErrWrongMasterPassword) {
		staleErr := fmt.Errorf("%w: saved secret is stale and was removed; run 'pwd-manager touchid enable' again", ErrBiometricUnavailable)
		return model.PwdFile{}, errors.Join(staleErr, disableBiometric(bio))
	}
	return pwdObj, err
}

// EnableBiometric checks Touch ID, verifies the typed master password against
// the store and saves it in the Keychain, then writes the opt-in marker.
func EnableBiometric() error {
	return enableBiometric(systemBiometrics(), func() ([]byte, error) {
		return PromptPasswordErr("Enter your master password:")
	})
}

func enableBiometric(bio biometrics, prompt func() ([]byte, error)) error {
	if err := requireStoreFile(); err != nil {
		return fmt.Errorf("open password store: %w", err)
	}
	if err := bio.authenticate(enableReason); err != nil {
		return fmt.Errorf("enable touch id: %w", err)
	}
	pwd, err := prompt()
	if err != nil {
		return fmt.Errorf("read master password: %w", err)
	}
	defer wipeBytes(pwd)
	if _, err := unlockWithPassword(pwd); err != nil {
		return fmt.Errorf("verify master password: %w", err)
	}
	return saveBiometricSecret(bio, pwd)
}

// saveBiometricSecret stores pwd in the Keychain and writes the marker; when
// the marker cannot be written the saved secret is removed again.
func saveBiometricSecret(bio biometrics, pwd []byte) error {
	if err := bio.saveSecret(pwd); err != nil {
		return fmt.Errorf("save master password for touch id: %w", err)
	}
	markerPath, err := resolveHomePath(BiometricMarkerName)
	if err == nil {
		err = writeSensitiveFileAtomic(markerPath, nil)
	}
	if err != nil {
		markerErr := fmt.Errorf("write touch id marker: %w", err)
		return errors.Join(markerErr, bio.deleteSecret())
	}
	return nil
}

// DisableBiometric removes the opt-in marker and the Keychain secret.
func DisableBiometric() error {
	return disableBiometric(systemBiometrics())
}

func disableBiometric(bio biometrics) error {
	markerPath, err := resolveHomePath(BiometricMarkerName)
	if err != nil {
		return err
	}
	if err := removeSensitiveFileIfPresent(markerPath); err != nil {
		return fmt.Errorf("remove touch id marker: %w", err)
	}
	// Builds without Touch ID support could never have saved a secret.
	if err := bio.deleteSecret(); err != nil && !errors.Is(err, biometric.ErrUnavailable) {
		return fmt.Errorf("delete saved master password: %w", err)
	}
	return nil
}

// RefreshBiometricSecret replaces the Keychain secret with a rotated master
// password while Touch ID is enabled. If that fails, Touch ID is disabled so
// a stale secret is never offered, and the error says so.
func RefreshBiometricSecret(password []byte) error {
	return refreshBiometricSecret(systemBiometrics(), password)
}

func refreshBiometricSecret(bio biometrics, password []byte) error {
	enabled, err := BiometricEnabled()
	if err != nil || !enabled {
		return err
	}
	if err := bio.saveSecret(password); err != nil {
		saveErr := fmt.Errorf("update touch id secret, touch id unlock disabled: %w", err)
		return errors.Join(saveErr, disableBiometric(bio))
	}
	return nil
}
