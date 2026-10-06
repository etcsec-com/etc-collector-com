//go:build windows

package saas

import "golang.org/x/sys/windows"

// isProcessAlive checks if a process with the given PID is still running.
func isProcessAlive(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	windows.CloseHandle(handle)
	return true
}
