//go:build windows

package daemon

import (
	"testing"
	"unsafe"
)

// Retain the allocation at the release boundary so the test can inspect it
// without reading freed memory. GlobalSize accepts the same handle argument
// as GlobalFree but does not release or modify the allocation.
func TestFreeZeroedGlobal_ErasesRejectedClipboardSecret(t *testing.T) {
	originalFree := procGlobalFree
	procGlobalFree = kernel32.NewProc("GlobalSize")
	t.Cleanup(func() { procGlobalFree = originalFree })
	for _, size := range []uintptr{2, 34, 4096} {
		handle, _, err := procGlobalAlloc.Call(gmemMoveable, size)
		if handle == 0 {
			t.Fatalf("allocate test secret: %v", err)
		}
		func() {
			defer originalFree.Call(handle)
			ptr, _, err := procGlobalLock.Call(handle)
			if ptr == 0 {
				t.Fatalf("lock test secret: %v", err)
			}
			data := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(size))
			for i := range data {
				data[i] = 0x73
			}
			procGlobalUnlock.Call(handle)

			freeZeroedGlobal(handle, size)

			ptr, _, err = procGlobalLock.Call(handle)
			if ptr == 0 {
				t.Fatalf("lock retained allocation: %v", err)
			}
			defer procGlobalUnlock.Call(handle)
			for i, b := range unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(size)) {
				if b != 0 {
					t.Fatalf("size %d: secret byte %d was not erased before release", size, i)
				}
			}
		}()
	}
}
