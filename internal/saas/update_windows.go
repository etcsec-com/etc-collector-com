//go:build windows

package saas

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// launchWatcher starts a detached watcher process that will perform the binary swap.
// The watcher is the same etc-collector binary invoked with "update watch" flags.
func launchWatcher(binaryPath, newBinaryPath, backupPath, stagingDir string) error {
	logFile := filepath.Join(filepath.Dir(binaryPath), "update.log")

	cmd := exec.Command(binaryPath, "update", "watch",
		"--pid", strconv.Itoa(os.Getpid()),
		"--binary", binaryPath,
		"--new-binary", newBinaryPath,
		"--backup", backupPath,
		"--staging", stagingDir,
		"--log-file", logFile,
	)

	// Detach: CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008,
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch update watcher: %w", err)
	}

	return nil
}

// performBinarySwap is the Windows entry point for the post-staging swap.
// Windows can't rename a running .exe in-process, so we keep the legacy
// fork-watcher pattern: launch a detached watcher, signal SaaS success,
// then exit so the SCM marks us STOPPED and the watcher takes over.
func (d *Daemon) performBinarySwap(cmd Command, startedAt string, params *updateParams, binaryPath string, staged *stagedUpdate) {
	backupPath := binaryPath + ".bak"

	d.logger.Info("Launching update watcher (Windows)",
		"binaryPath", binaryPath,
		"newBinaryPath", staged.NewBinaryPath,
		"backupPath", backupPath,
	)
	if err := launchWatcher(binaryPath, staged.NewBinaryPath, backupPath, staged.StagingDir); err != nil {
		d.logger.Error("Watcher launch failed", "commandId", cmd.CommandID, "error", err)
		d.submitError(cmd.CommandID, startedAt, "UPDATE_FAILED", "watcher launch failed", err.Error())
		return
	}

	d.submitSuccess(cmd.CommandID, startedAt, map[string]string{
		"note":          "watcher launched (Windows)",
		"targetVersion": params.targetVersion,
		"method":        "fork-watcher",
	})

	// Stop daemon then exit. os.Exit is required so the SCM Execute() handler
	// returns and Windows marks the service STOPPED. The detached watcher
	// then renames + restarts.
	d.logger.Info("Update watcher launched, stopping daemon for binary replacement")
	go func() {
		time.Sleep(2 * time.Second)
		d.Stop()
		os.Exit(0)
	}()
}
