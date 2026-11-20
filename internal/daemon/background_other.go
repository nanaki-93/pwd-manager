//go:build !(darwin && cgo)

package daemon

// setBackgroundActivationPolicy does nothing: only macOS shows a Dock icon
// for the running app.
func setBackgroundActivationPolicy() {}

// disableRegularActivationPolicy does nothing: only GLFW on macOS restores
// the Regular activation policy on launch.
func disableRegularActivationPolicy() {}
