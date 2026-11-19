//go:build darwin && cgo

package biometric

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework LocalAuthentication -framework Security
#include <stdlib.h>
#include <string.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

enum { authOK = 0, authUnavailable = 1, authCanceled = 2, authFailed = 3 };

// authenticateBiometric shows the Touch ID prompt and blocks until the user
// answers; the reply runs on a LocalAuthentication queue, not this thread.
static int authenticateBiometric(const char *reason) {
	@autoreleasepool {
		LAContext *ctx = [[[LAContext alloc] init] autorelease];
		LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
		if (![ctx canEvaluatePolicy:policy error:nil]) {
			return authUnavailable;
		}
		dispatch_semaphore_t done = dispatch_semaphore_create(0);
		__block int result = authFailed;
		[ctx evaluatePolicy:policy
		    localizedReason:[NSString stringWithUTF8String:reason]
		              reply:^(BOOL success, NSError *error) {
			if (success) {
				result = authOK;
			} else if (error.code == LAErrorUserCancel || error.code == LAErrorSystemCancel ||
			           error.code == LAErrorAppCancel || error.code == LAErrorUserFallback) {
				result = authCanceled;
			} else if (error.code == LAErrorBiometryNotAvailable || error.code == LAErrorBiometryNotEnrolled ||
			           error.code == LAErrorBiometryLockout) {
				result = authUnavailable;
			}
			dispatch_semaphore_signal(done);
		}];
		dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
		dispatch_release(done);
		return result;
	}
}

// keychainQuery matches the generic-password item holding the master secret.
static NSMutableDictionary *keychainQuery(void) {
	return [NSMutableDictionary dictionaryWithDictionary:@{
		(id)kSecClass: (id)kSecClassGenericPassword,
		(id)kSecAttrService: @"pwd-manager",
		(id)kSecAttrAccount: @"master",
	}];
}

// keychainDelete removes the item; a missing item is not an error.
static OSStatus keychainDelete(void) {
	@autoreleasepool {
		OSStatus status = SecItemDelete((CFDictionaryRef)keychainQuery());
		return status == errSecItemNotFound ? errSecSuccess : status;
	}
}

// keychainSave replaces the item with secret, readable only on this device
// while it is unlocked.
static OSStatus keychainSave(const void *secret, size_t secretLen) {
	@autoreleasepool {
		OSStatus status = keychainDelete();
		if (status != errSecSuccess) {
			return status;
		}
		NSMutableDictionary *item = keychainQuery();
		item[(id)kSecValueData] = [NSData dataWithBytes:secret length:secretLen];
		item[(id)kSecAttrAccessible] = (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
		return SecItemAdd((CFDictionaryRef)item, NULL);
	}
}

// keychainLoad copies the item's data into a malloc'd buffer the caller
// wipes and frees.
static OSStatus keychainLoad(void **out, size_t *outLen) {
	@autoreleasepool {
		NSMutableDictionary *query = keychainQuery();
		query[(id)kSecReturnData] = @YES;
		query[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
		CFTypeRef result = NULL;
		OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &result);
		if (status != errSecSuccess) {
			return status;
		}
		NSData *data = (NSData *)result;
		*outLen = [data length];
		*out = malloc(*outLen > 0 ? *outLen : 1);
		if (*out == NULL) {
			CFRelease(result);
			return errSecAllocate;
		}
		memcpy(*out, [data bytes], *outLen);
		CFRelease(result);
		return errSecSuccess;
	}
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Authenticate shows the Touch ID prompt with reason and returns nil once the
// user authenticated, ErrUnavailable when Touch ID cannot be used, ErrCanceled
// when the prompt was dismissed and ErrFailed otherwise.
func Authenticate(reason string) error {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	switch C.authenticateBiometric(cReason) {
	case C.authOK:
		return nil
	case C.authUnavailable:
		return ErrUnavailable
	case C.authCanceled:
		return ErrCanceled
	default:
		return ErrFailed
	}
}

// SaveSecret stores secret in the Keychain item, replacing any previous one.
func SaveSecret(secret []byte) error {
	buf := C.CBytes(secret)
	defer func() {
		C.memset(buf, 0, C.size_t(len(secret)))
		C.free(buf)
	}()
	if status := C.keychainSave(buf, C.size_t(len(secret))); status != C.errSecSuccess {
		return fmt.Errorf("save keychain item: OSStatus %d", int(status))
	}
	return nil
}

// LoadSecret returns the secret stored in the Keychain item, or an error
// matching ErrUnavailable when there is none. The caller wipes it.
func LoadSecret() ([]byte, error) {
	var buf unsafe.Pointer
	var size C.size_t
	status := C.keychainLoad(&buf, &size)
	if status == C.errSecItemNotFound {
		return nil, fmt.Errorf("load keychain item: %w: no saved secret", ErrUnavailable)
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("load keychain item: OSStatus %d", int(status))
	}
	defer func() {
		C.memset(buf, 0, size)
		C.free(buf)
	}()
	return C.GoBytes(buf, C.int(size)), nil
}

// DeleteSecret removes the Keychain item; a missing item is not an error.
func DeleteSecret() error {
	if status := C.keychainDelete(); status != C.errSecSuccess {
		return fmt.Errorf("delete keychain item: OSStatus %d", int(status))
	}
	return nil
}
