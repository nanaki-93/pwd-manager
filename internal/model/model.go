/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package model

type PwdFile struct {
	MasterPassword string
	SavedPasswords map[string]string
}
