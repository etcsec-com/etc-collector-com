//go:build !windows

package saas

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// launchWatcher starts a detached watcher process that will perform the binary swap.
// The watcher is the same etc-collector binary invoked with "update watch" flags.
//
// On systemd, the default KillMode=control-group kills all processes in the
// service's cgroup when the unit stops — including child processes, even those
// with Setsid. We use systemd-run --scope to launch the watcher in its own
// transient scope unit, outside the service's cgroup. If systemd-run is not
// available (non-systemd systems), we fall back to Setsid which works when
// KillMode is not control-group.
func launchWatcher(binaryPath, newBinaryPath, backupPath, stagingDir string) error {
	logFile := filepath.Join(filepath.Dir(binaryPath), "update.log")

	watcherArgs := []string{
		"update", "watch",
		"--pid", strconv.Itoa(os.Getpid()),
		"--binary", binaryPath,
		"--new-binary", newBinaryPath,
		"--backup", backupPath,
		"--staging", stagingDir,
		"--log-file", logFile,
	}

	// Try systemd-run first to escape the service's cgroup
	if _, err := exec.LookPath("systemd-run"); err == nil {
		sdArgs := []string{
			"--scope",                         // transient scope (not a service)
			"--unit=etcsec-collector-updater", // descriptive unit name
			"--description=ETC Collector Updater",
			binaryPath,
		}
		sdArgs = append(sdArgs, watcherArgs...)

		cmd := exec.Command("systemd-run", sdArgs...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil

		if err := cmd.Start(); err == nil {
			return nil
		}
		// systemd-run failed, fall through to direct launch
	}

	// Fallback: direct launch with Setsid (works on non-systemd systems
	// or when KillMode=process is set)
	cmd := exec.Command(binaryPath, watcherArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch update watcher: %w", err)
	}

	return nil
}
