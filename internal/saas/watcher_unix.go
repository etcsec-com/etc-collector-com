//go:build !windows

package saas

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const watcherServiceName = "etcsec-collector"

// waitForPID waits for the given process to exit by polling kill(pid, 0).
// Signal 0 checks if the process exists without sending a signal.
// Returns nil when the process no longer exists (ESRCH).
func waitForPID(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if err == syscall.ESRCH {
			return nil // Process gone
		}
		if err != nil && err != syscall.EPERM {
			return nil // Some other error, assume gone
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for pid %d after %v", pid, timeout)
}

// waitForServiceStopped polls systemctl is-active until inactive or timeout.
func waitForServiceStopped(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isServiceRunning() {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for service to stop after %v", timeout)
}

// isServiceRunning checks if the systemd service is active.
func isServiceRunning() bool {
	err := exec.Command("systemctl", "is-active", "--quiet", watcherServiceName).Run()
	return err == nil
}

// startService starts the systemd service.
func startService() error {
	out, err := exec.Command("systemctl", "start", watcherServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl start: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// stopService stops the systemd service.
func stopService() error {
	out, err := exec.Command("systemctl", "stop", watcherServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// setExecutable sets the executable bit on the binary.
func setExecutable(path string) error {
	return os.Chmod(path, 0755)
}
