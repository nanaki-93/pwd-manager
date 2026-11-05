//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	cfUnicodeText        = 13
	gmemMoveable         = 0x0002
	openClipboardTimeout = time.Second
	openClipboardRetry   = 10 * time.Millisecond
)

var (
	user32                       = syscall.NewLazyDLL("user32.dll")
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procOpenClipboard            = user32.NewProc("OpenClipboard")
	procCloseClipboard           = user32.NewProc("CloseClipboard")
	procEmptyClipboard           = user32.NewProc("EmptyClipboard")
	procSetClipboardData         = user32.NewProc("SetClipboardData")
	procRegisterClipboardFormatW = user32.NewProc("RegisterClipboardFormatW")
	procGlobalAlloc              = kernel32.NewProc("GlobalAlloc")
	procGlobalFree               = kernel32.NewProc("GlobalFree")
	procGlobalLock               = kernel32.NewProc("GlobalLock")
	procGlobalUnlock             = kernel32.NewProc("GlobalUnlock")
	procRtlMoveMemory            = kernel32.NewProc("RtlMoveMemory")
)

// nativeConcealedClipboardWriter returns the Win32 writer that excludes the
// password from clipboard history and cloud sync.
func nativeConcealedClipboardWriter() func(pwd string, flags []string) error {
	return writeWindowsConcealedClipboard
}

// writeWindowsConcealedClipboard sets the password text and one registered
// clipboard format per flag inside a single Open/CloseClipboard session, so
// clipboard listeners are notified only once all hints are present. If any
// format cannot be set the clipboard is emptied before it is closed.
func writeWindowsConcealedClipboard(pwd string, flags []string) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := openClipboard(); err != nil {
		return err
	}
	defer func() {
		if ok, _, closeErr := procCloseClipboard.Call(); ok == 0 {
			err = errors.Join(err, fmt.Errorf("close clipboard: %w", closeErr))
		}
	}()
	if ok, _, emptyErr := procEmptyClipboard.Call(); ok == 0 {
		return fmt.Errorf("empty clipboard: %w", emptyErr)
	}
	if err := setConcealedContents(pwd, flags); err != nil {
		if ok, _, emptyErr := procEmptyClipboard.Call(); ok == 0 {
			return errors.Join(err, fmt.Errorf("empty clipboard after failed write: %w", emptyErr))
		}
		return err
	}
	return nil
}

// openClipboard retries OpenClipboard for openClipboardTimeout, since another
// process may briefly hold the clipboard open.
func openClipboard() error {
	deadline := time.Now().Add(openClipboardTimeout)
	for {
		ok, _, err := procOpenClipboard.Call(0)
		if ok != 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("open clipboard: %w", err)
		}
		time.Sleep(openClipboardRetry)
	}
}

// setConcealedContents sets pwd as CF_UNICODETEXT and each flag as a
// registered format; the caller has the clipboard open and emptied.
func setConcealedContents(pwd string, flags []string) error {
	text, err := syscall.UTF16FromString(pwd)
	if err != nil {
		return fmt.Errorf("encode password for clipboard: %w", err)
	}
	defer clear(text)
	if err := setClipboardBytes(cfUnicodeText, unsafe.Pointer(&text[0]), uintptr(len(text)*2)); err != nil {
		return fmt.Errorf("set clipboard text: %w", err)
	}
	for _, flag := range flags {
		if err := setClipboardHint(flag); err != nil {
			return err
		}
	}
	return nil
}

// setClipboardHint sets a "Name" or "Name=value" flag as the registered
// format Name holding a DWORD: 1 for "true", otherwise 0 (as
// CanIncludeInClipboardHistory expects; marker formats ignore the value).
func setClipboardHint(flag string) error {
	name, value, _ := strings.Cut(flag, "=")
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("encode clipboard format %q: %w", name, err)
	}
	format, _, regErr := procRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(namePtr)))
	if format == 0 {
		return fmt.Errorf("register clipboard format %q: %w", name, regErr)
	}
	var data uint32
	if value == "true" {
		data = 1
	}
	if err := setClipboardBytes(format, unsafe.Pointer(&data), unsafe.Sizeof(data)); err != nil {
		return fmt.Errorf("set clipboard format %q: %w", name, err)
	}
	return nil
}

// setClipboardBytes copies size bytes from src into movable global memory
// and hands it to the clipboard as format; the clipboard then owns it.
func setClipboardBytes(format uintptr, src unsafe.Pointer, size uintptr) error {
	handle, _, err := procGlobalAlloc.Call(gmemMoveable, size)
	if handle == 0 {
		return fmt.Errorf("allocate clipboard memory: %w", err)
	}
	dst, _, err := procGlobalLock.Call(handle)
	if dst == 0 {
		procGlobalFree.Call(handle) // best effort: the lock error is returned
		return fmt.Errorf("lock clipboard memory: %w", err)
	}
	procRtlMoveMemory.Call(dst, uintptr(src), size)
	// GlobalUnlock returns 0 once the lock count drops to zero, which is the
	// expected outcome here rather than a failure.
	procGlobalUnlock.Call(handle)
	if ok, _, err := procSetClipboardData.Call(format, handle); ok == 0 {
		freeZeroedGlobal(handle, size) // best effort: the set error is returned
		return fmt.Errorf("set clipboard data: %w", err)
	}
	return nil
}

// freeZeroedGlobal overwrites the size bytes of the movable global memory
// handle with zeros before freeing it, so a password the clipboard refused
// is not left in the released heap block. It is best effort: if the block
// cannot be locked it is still freed.
func freeZeroedGlobal(handle, size uintptr) {
	if dst, _, _ := procGlobalLock.Call(handle); dst != 0 {
		zeros := make([]byte, size)
		procRtlMoveMemory.Call(dst, uintptr(unsafe.Pointer(&zeros[0])), size)
		procGlobalUnlock.Call(handle)
	}
	procGlobalFree.Call(handle)
}
