//go:build darwin && cgo

package daemon

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit
#import <AppKit/AppKit.h>

// setAccessoryActivationPolicy makes the running app an accessory app: no
// Dock icon and no menu bar, while its windows can still be shown. It then
// activates the app and orders each visible window in front of other apps,
// keeping its normal window level, so a shown accessory window takes focus.
static void setAccessoryActivationPolicy(void) {
	@autoreleasepool {
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		[NSApp activateIgnoringOtherApps:YES];
#pragma clang diagnostic pop
		for (NSWindow *window in [NSApp windows]) {
			if ([window isVisible]) {
				[window makeKeyAndOrderFront:nil];
				[window orderFrontRegardless];
			}
		}
	}
}
*/
import "C"

import "github.com/go-gl/glfw/v3.3/glfw"

// disableRegularActivationPolicy stops GLFW's Cocoa menubar setup, which on
// launch switches a non-bundled app back to the Regular activation policy and
// so restores the Dock icon hideFromDock removed. It must run before
// glfw.Init, that is before the Fyne app is created.
func disableRegularActivationPolicy() {
	glfw.InitHint(glfw.CocoaMenubar, glfw.False)
}

// setBackgroundActivationPolicy hides the app from the Dock by switching
// NSApp to the Accessory activation policy. It must run on the main thread.
func setBackgroundActivationPolicy() {
	C.setAccessoryActivationPolicy()
}
