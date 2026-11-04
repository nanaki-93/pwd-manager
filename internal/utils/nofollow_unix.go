//go:build unix

/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import "syscall"

// openNoFollow makes open fail when the final path element is a symlink.
const openNoFollow = syscall.O_NOFOLLOW
