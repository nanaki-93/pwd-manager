//go:build !(darwin && cgo)

package daemon

// setBackgroundActivationPolicy does nothing: only macOS shows a Dock icon
// for the running app.
func setBackgroundActivationPolicy() {}
