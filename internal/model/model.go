/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package model

type PwdFile struct {
	MasterPassword string
	SavedPasswords map[string]string
}

// NewPwdFile returns a PwdFile with the given master password and an
// initialized, empty SavedPasswords map that is safe to assign to.
func NewPwdFile(master string) *PwdFile {
	return &PwdFile{
		MasterPassword: master,
		SavedPasswords: make(map[string]string),
	}
}
