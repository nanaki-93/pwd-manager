//go:build darwin && cgo

package daemon

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit
#import <AppKit/AppKit.h>

// setAccessoryActivationPolicy makes the running app an accessory app: no
// Dock icon and no menu bar, while its windows can still be shown.
static void setAccessoryActivationPolicy(void) {
	@autoreleasepool {
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
	}
}
*/
import "C"

// setBackgroundActivationPolicy hides the app from the Dock by switching
// NSApp to the Accessory activation policy. It must run on the main thread.
func setBackgroundActivationPolicy() {
	C.setAccessoryActivationPolicy()
}
