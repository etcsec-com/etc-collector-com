//go:build windows

package saas

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const watcherServiceName = "EtcSecCollector"

// waitForPID waits for the given process to exit using Windows API.
// Uses OpenProcess + WaitForSingleObject for efficient blocking wait.
func waitForPID(pid int, timeout time.Duration) error {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// Process may already be gone
		return nil
	}
	defer windows.CloseHandle(handle)

	ms := uint32(timeout.Milliseconds())
	event, err := windows.WaitForSingleObject(handle, ms)
	if err != nil {
		return fmt.Errorf("WaitForSingleObject: %w", err)
	}
	if event == uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("timeout waiting for pid %d after %v", pid, timeout)
	}
	return nil
}

// waitForServiceStopped polls sc query until STOPPED or timeout.
func waitForServiceStopped(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("sc", "query", watcherServiceName).CombinedOutput()
		if err != nil {
			return nil // sc query failed, assume stopped
		}
		if strings.Contains(string(out), "STOPPED") {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for service to stop after %v", timeout)
}

// isServiceRunning checks if the service is in RUNNING state.
func isServiceRunning() bool {
	out, err := exec.Command("sc", "query", watcherServiceName).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "RUNNING")
}

// startService starts the Windows service via sc start.
func startService() error {
	out, err := exec.Command("sc", "start", watcherServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc start: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// stopService stops the Windows service via sc stop.
func stopService() error {
	out, err := exec.Command("sc", "stop", watcherServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc stop: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// setExecutable is a noop on Windows.
func setExecutable(path string) error {
	return nil
}
