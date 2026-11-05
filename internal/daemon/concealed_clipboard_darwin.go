//go:build darwin && cgo

package daemon

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit
#include <stdlib.h>
#include <string.h>
#import <AppKit/AppKit.h>

// writeConcealedPasteboard replaces the general pasteboard contents with one
// item holding the UTF-8 text plus an empty marker for each newline-separated
// type, so the hints are published in the same write as the text.
static int writeConcealedPasteboard(const void *text, size_t textLen, const char *types) {
	@autoreleasepool {
		NSString *str = [[[NSString alloc] initWithBytes:text length:textLen encoding:NSUTF8StringEncoding] autorelease];
		if (str == nil) {
			return 1;
		}
		NSPasteboardItem *item = [[[NSPasteboardItem alloc] init] autorelease];
		if (![item setString:str forType:NSPasteboardTypeString]) {
			return 2;
		}
		for (NSString *type in [[NSString stringWithUTF8String:types] componentsSeparatedByString:@"\n"]) {
			if ([type length] > 0 && ![item setData:[NSData data] forType:type]) {
				return 3;
			}
		}
		NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
		[pasteboard clearContents];
		if (![pasteboard writeObjects:@[item]]) {
			return 4;
		}
		return 0;
	}
}
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

// nativeConcealedClipboardWriter returns the NSPasteboard writer that marks
// the password with the org.nspasteboard concealed/transient types.
func nativeConcealedClipboardWriter() func(pwd string, flags []string) error {
	return writeDarwinConcealedClipboard
}

// writeDarwinConcealedClipboard writes pwd as one pasteboard item that also
// carries each flag as a pasteboard type. The C copy of pwd is zeroed before
// it is freed.
func writeDarwinConcealedClipboard(pwd string, flags []string) error {
	text := C.CString(pwd)
	defer func() {
		C.memset(unsafe.Pointer(text), 0, C.size_t(len(pwd)))
		C.free(unsafe.Pointer(text))
	}()
	types := C.CString(strings.Join(flags, "\n"))
	defer C.free(unsafe.Pointer(types))

	if status := C.writeConcealedPasteboard(unsafe.Pointer(text), C.size_t(len(pwd)), types); status != 0 {
		return fmt.Errorf("write concealed pasteboard item: step %d failed", int(status))
	}
	return nil
}
