//go:build !unix

/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

// openNoFollow is zero where the platform has no O_NOFOLLOW (e.g. Windows);
// readSensitiveFile still rejects symlinks via Lstat and os.SameFile.
const openNoFollow = 0
