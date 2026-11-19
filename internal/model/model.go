/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package model

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

type PwdFile struct {
	MasterPassword string
	SavedPasswords map[string]string
}

// MaxPwdNameLen bounds the length, in characters, of an entry name.
const MaxPwdNameLen = 128

// ErrInvalidPwdName reports an entry name that is too long, not valid UTF-8
// or contains non-printable characters such as control or escape bytes.
var ErrInvalidPwdName = errors.New("invalid password name")

// ValidatePwdName rejects names that could inject terminal escape sequences or
// control characters when echoed in prompts or listed from the vault later.
func ValidatePwdName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalidPwdName)
	}
	if n := utf8.RuneCountInString(name); n > MaxPwdNameLen {
		return fmt.Errorf("%w: %d characters exceeds the maximum of %d", ErrInvalidPwdName, n, MaxPwdNameLen)
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("%w: contains non-printable character %q", ErrInvalidPwdName, r)
		}
	}
	return nil
}
