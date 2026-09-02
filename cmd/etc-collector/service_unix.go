//go:build !windows

package main

import "errors"

// runService is a no-op on non-Windows systems
func runService(isDebug bool) error {
	return errors.New("Windows service mode not supported on this platform. Use systemd instead")
}

// runServerAsWindowsService is a no-op on non-Windows systems — B_184
// (T_089). isWindowsServiceContext() always returns false here, so
// runServer's own caller into this never actually fires on this platform;
// this stub only exists so server.go compiles everywhere.
func runServerAsWindowsService() error {
	return errors.New("Windows service mode not supported on this platform. Use systemd instead")
}

// installWindowsService is a no-op on non-Windows systems
func installWindowsService() error {
	return errors.New("Windows service installation not supported on this platform")
}

// uninstallService is a no-op on non-Windows systems
func uninstallService() error {
	return errors.New("Windows service uninstallation not supported on this platform")
}

// startWindowsService is a no-op on non-Windows systems
func startWindowsService() error {
	return errors.New("Windows service not supported on this platform")
}

// stopWindowsService is a no-op on non-Windows systems
func stopWindowsService() error {
	return errors.New("Windows service not supported on this platform")
}

// statusWindowsService is a no-op on non-Windows systems
func statusWindowsService() error {
	return errors.New("Windows service not supported on this platform")
}

// isWindowsService always returns false on non-Windows systems
func isWindowsService() bool {
	return false
}
