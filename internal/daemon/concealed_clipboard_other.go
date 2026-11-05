//go:build !windows && !(darwin && cgo)

package daemon

// nativeConcealedClipboardWriter returns nil: this platform has no native
// writer that attaches concealment hints, so passwords are written unhinted.
func nativeConcealedClipboardWriter() func(pwd string, flags []string) error {
	return nil
}
