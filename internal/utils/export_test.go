package utils

// SetKDFForTesting overrides the PBKDF2 function used for master hashes and store
// keys and returns a restore callback. It lives in a _test.go file so production
// binaries cannot replace the KDF: fn must be deterministic in all its arguments
// so stores written with it can be read back.
func SetKDFForTesting(fn func(password, salt []byte, iter, keyLen int) []byte) func() {
	prev := kdf
	kdf = fn
	return func() {
		kdf = prev
	}
}

// SetExitFunc overrides ExitFunc and returns a restore callback.
func SetExitFunc(fn func(int)) func() {
	prev := ExitFunc
	ExitFunc = fn
	return func() { ExitFunc = prev }
}

// SetReadPasswordStdin overrides ReadPasswordStdin and returns a restore callback.
func SetReadPasswordStdin(fn func() ([]byte, error)) func() {
	prev := ReadPasswordStdin
	ReadPasswordStdin = fn
	return func() { ReadPasswordStdin = prev }
}
