//go:build !darwin || !cgo

package biometric

// Authenticate reports ErrUnavailable: Touch ID needs darwin with cgo.
func Authenticate(reason string) error {
	return ErrUnavailable
}

// SaveSecret reports ErrUnavailable: the Keychain needs darwin with cgo.
func SaveSecret(secret []byte) error {
	return ErrUnavailable
}

// LoadSecret reports ErrUnavailable: the Keychain needs darwin with cgo.
func LoadSecret() ([]byte, error) {
	return nil, ErrUnavailable
}

// DeleteSecret reports ErrUnavailable: the Keychain needs darwin with cgo.
func DeleteSecret() error {
	return ErrUnavailable
}
