//go:build !windows

package saas

import "syscall"

// isProcessAlive checks if a process with the given PID is still running.
func isProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
