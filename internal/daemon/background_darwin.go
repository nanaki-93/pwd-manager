//go:build darwin && cgo

package daemon

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit
#import <AppKit/AppKit.h>

// setAccessoryActivationPolicy makes the running app an accessory app: no
// Dock icon and no menu bar, while its windows can still be shown. It then
// activates the app so a shown accessory window still takes focus.
static void setAccessoryActivationPolicy(void) {
	@autoreleasepool {
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		[NSApp activateIgnoringOtherApps:YES];
#pragma clang diagnostic pop
	}
}
*/
import "C"

// setBackgroundActivationPolicy hides the app from the Dock by switching
// NSApp to the Accessory activation policy. It must run on the main thread.
func setBackgroundActivationPolicy() {
	C.setAccessoryActivationPolicy()
}
