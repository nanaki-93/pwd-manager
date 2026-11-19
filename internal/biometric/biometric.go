// Package biometric unlocks with Touch ID: it shows the LocalAuthentication
// prompt and keeps the master secret in a macOS Keychain generic-password
// item. Builds other than darwin with cgo report ErrUnavailable.
package biometric

import "errors"

var (
	// ErrUnavailable reports that Touch ID or the Keychain item cannot be used.
	ErrUnavailable = errors.New("touch id unavailable")
	// ErrCanceled reports that the user dismissed the Touch ID prompt.
	ErrCanceled = errors.New("touch id prompt canceled")
	// ErrFailed reports a Touch ID prompt that did not authenticate the user.
	ErrFailed = errors.New("touch id authentication failed")
)
