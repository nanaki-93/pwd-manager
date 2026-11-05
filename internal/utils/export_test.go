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
