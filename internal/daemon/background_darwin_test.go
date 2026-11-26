//go:build darwin && cgo

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Compile the actual cgo helper with a fake NSApp: Go test files cannot import C,
// and exercising real AppKit windows requires an interactive desktop session.
func TestAccessoryPolicyKeepsOnlyVisibleWindowsOnTop(t *testing.T) {
	source, err := os.ReadFile("background_darwin.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	start := strings.Index(text, "static void setAccessoryActivationPolicy(void) {")
	end := strings.Index(text, "\n*/")
	if start < 0 || end < start {
		t.Fatal("cannot locate native activation helper")
	}
	harness := `#import <AppKit/AppKit.h>
#include <stdlib.h>
@interface FakeWindow : NSObject
@property BOOL visible;
@property int keyCalls, frontCalls, levelCalls, behaviorCalls;
@property NSInteger level;
@property NSWindowCollectionBehavior behavior;
@property NSMutableString *events;
- (BOOL)isVisible;
- (void)makeKeyAndOrderFront:(id)sender;
- (void)orderFrontRegardless;
- (void)setLevel:(NSInteger)level;
- (void)setCollectionBehavior:(NSWindowCollectionBehavior)behavior;
@end
@implementation FakeWindow
- (BOOL)isVisible { return _visible; }
- (void)makeKeyAndOrderFront:(id)sender { _keyCalls++; [_events appendString:@"K"]; }
- (void)orderFrontRegardless { _frontCalls++; [_events appendString:@"F"]; }
- (void)setLevel:(NSInteger)level { _levelCalls++; _level = level; [_events appendString:@"L"]; }
- (void)setCollectionBehavior:(NSWindowCollectionBehavior)behavior { _behaviorCalls++; _behavior = behavior; [_events appendString:@"B"]; }
@end
@interface FakeApp : NSObject
@property NSArray *windows;
@property NSMutableString *events;
- (BOOL)setActivationPolicy:(NSApplicationActivationPolicy)policy;
- (void)activateIgnoringOtherApps:(BOOL)flag;
@end
@implementation FakeApp
- (BOOL)setActivationPolicy:(NSApplicationActivationPolicy)policy {
    [_events appendString:policy == NSApplicationActivationPolicyAccessory ? @"P" : @"X"]; return YES;
}
- (void)activateIgnoringOtherApps:(BOOL)flag { [_events appendString:flag ? @"A" : @"X"]; }
@end
static FakeApp *fakeApp;
#undef NSApp
#define NSApp fakeApp
` + text[start:end] + `
int main(void) {
    @autoreleasepool {
        fakeApp = [FakeApp new];
        fakeApp.events = [NSMutableString string];
        fakeApp.windows = @[];
        setAccessoryActivationPolicy();
        if (![fakeApp.events isEqualToString:@"PA"]) return 1;
        FakeWindow *first = [FakeWindow new], *hidden = [FakeWindow new], *last = [FakeWindow new];
        first.visible = YES; last.visible = YES;
        first.events = fakeApp.events; hidden.events = fakeApp.events; last.events = fakeApp.events;
        fakeApp.windows = @[first, hidden, last];
        setAccessoryActivationPolicy();
        if (![fakeApp.events isEqualToString:@"PAPALBKFLBKF"]) return 2;
        if (first.keyCalls != 1 || first.frontCalls != 1 || last.keyCalls != 1 || last.frontCalls != 1) return 3;
        if (hidden.keyCalls || hidden.frontCalls) return 4;
        if (hidden.levelCalls || hidden.behaviorCalls) return 5;
        NSWindowCollectionBehavior want = NSWindowCollectionBehaviorMoveToActiveSpace | NSWindowCollectionBehaviorFullScreenAuxiliary;
        for (FakeWindow *w in @[first, last]) {
            if (w.levelCalls != 1 || w.level != NSFloatingWindowLevel) return 6;
            if (w.behaviorCalls != 1 || w.behavior != want) return 7;
        }
    }
    return 0;
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "helper.m")
	if err := os.WriteFile(path, []byte(harness), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "helper")
	if out, err := exec.Command("clang", "-fobjc-arc", "-framework", "AppKit", path, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile native helper harness: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("native helper violated activation/window ordering contract: %v\n%s", err, out)
	}
}
