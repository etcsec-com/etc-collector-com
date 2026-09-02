//go:build windows

package upgrade

import (
	"syscall"
	"unsafe"
)

// freeBytes uses GetDiskFreeSpaceExW to read available bytes for the volume
// containing path. Returns the caller-available value (FreeBytesAvailable),
// which honors disk quotas — same semantics as Unix's Bavail*Bsize.
func freeBytes(path string) (uint64, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	var freeAvail, totalBytes, totalFree uint64
	r1, _, e1 := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeAvail)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r1 == 0 {
		return 0, e1
	}
	return freeAvail, nil
}
