package saas

import (
	"fmt"
	"io"
	"os"
	"time"
)

// WatcherParams holds the parameters passed via CLI flags to the watcher process.
type WatcherParams struct {
	PID       int
	Binary    string // path to the current binary
	NewBinary string // path to the extracted new binary in staging
	Backup    string // backup path for rollback (binary + ".bak")
	Staging   string // staging directory to clean up
	LogFile   string // path to update.log
}

// RunWatcher is the main entry point for the watcher subprocess.
// Called from the "update watch" cobra command handler.
//
// Flow:
//  1. Wait for parent PID to exit
//  2. Wait for service to reach STOPPED state
//  3. Backup current binary
//  4. Copy new binary in place
//  5. Set executable permission (Unix)
//  6. Start service
//  7. Health check at 10s and 20s (crash-loop detection)
//  8. Rollback if health fails
//  9. Cleanup staging directory
func RunWatcher(params WatcherParams) {
	logWriter := openLogFile(params.LogFile)
	defer logWriter.Close()

	wlog := func(msg string, args ...interface{}) {
		ts := time.Now().Format("2006-01-02 15:04:05")
		line := fmt.Sprintf("[%s] %s\n", ts, fmt.Sprintf(msg, args...))
		logWriter.Write([]byte(line))
	}

	wlog("Update watcher started (pid=%d, parentPid=%d)", os.Getpid(), params.PID)
	wlog("  binary:     %s", params.Binary)
	wlog("  newBinary:  %s", params.NewBinary)
	wlog("  backup:     %s", params.Backup)
	wlog("  staging:    %s", params.Staging)

	// Step 1: Wait for parent process to exit
	wlog("Waiting for parent process %d to exit...", params.PID)
	if err := waitForPID(params.PID, 120*time.Second); err != nil {
		wlog("WARN: waiting for parent: %v (continuing anyway)", err)
	}
	wlog("Parent process exited")

	// Step 2: Wait for service to reach STOPPED state
	wlog("Waiting for service to reach STOPPED state...")
	if err := waitForServiceStopped(60 * time.Second); err != nil {
		wlog("WARN: service did not stop cleanly: %v", err)
		wlog("Attempting force stop...")
		if err := stopService(); err != nil {
			wlog("WARN: force stop failed: %v", err)
		}
		time.Sleep(5 * time.Second)
	}
	wlog("Service stopped")

	// Step 3: Backup current binary via rename.
	// On Windows, the watcher IS the binary being replaced (etc-collector.exe).
	// A running exe is locked by the OS loader and cannot be opened for write,
	// but os.Rename (MoveFile) works on locked files — it moves the directory
	// entry without touching the file contents. After rename, the original path
	// is free for writing.
	wlog("Backing up current binary to %s (rename)", params.Backup)
	os.Remove(params.Backup) // remove stale backup if present
	if err := os.Rename(params.Binary, params.Backup); err != nil {
		wlog("FATAL: backup rename failed: %v", err)
		watcherCleanup(params.Staging, wlog)
		return
	}
	wlog("Backup created (renamed)")

	// Step 4: Copy new binary to the now-free path
	wlog("Installing new binary from %s", params.NewBinary)
	if err := copyFile(params.NewBinary, params.Binary); err != nil {
		wlog("ERROR: copy new binary failed: %v, rolling back", err)
		os.Rename(params.Backup, params.Binary) // rename back (works on locked files)
		setExecutable(params.Binary)
		startService()
		watcherCleanup(params.Staging, wlog)
		return
	}
	wlog("New binary installed")

	// Step 5: Set executable permission (Unix: chmod +x, Windows: noop)
	if err := setExecutable(params.Binary); err != nil {
		wlog("WARN: set executable failed: %v", err)
	}

	// Step 6: Start service
	wlog("Starting service...")
	if err := startService(); err != nil {
		wlog("ERROR: service start failed: %v, rolling back", err)
		watcherRollback(params.Binary, params.Backup, wlog)
		watcherCleanup(params.Staging, wlog)
		return
	}
	wlog("Service start issued, waiting for stabilization")

	// Step 7: Health check at 10s
	time.Sleep(10 * time.Second)
	if !isServiceRunning() {
		wlog("Service NOT running at 10s check, rolling back")
		watcherRollback(params.Binary, params.Backup, wlog)
		watcherCleanup(params.Staging, wlog)
		return
	}
	wlog("Service running at 10s check, waiting for crash-loop detection")

	// Step 8: Health check at 20s (catches crash-loop)
	time.Sleep(10 * time.Second)
	if !isServiceRunning() {
		wlog("Service CRASHED after initial start (crash-loop detected), rolling back")
		watcherRollback(params.Binary, params.Backup, wlog)
		watcherCleanup(params.Staging, wlog)
		return
	}

	wlog("Update successful, service stable after 20s")
	watcherCleanup(params.Staging, wlog)
	wlog("Done")
}

// watcherRollback stops the service, restores the backup, and restarts.
// Uses os.Rename to move the backup back (works on locked files on Windows).
func watcherRollback(binaryPath, backupPath string, wlog func(string, ...interface{})) {
	wlog("Rolling back to previous version")
	stopService()
	time.Sleep(5 * time.Second)
	os.Remove(binaryPath) // remove the failed new binary (may fail if locked, that's ok)
	if err := os.Rename(backupPath, binaryPath); err != nil {
		wlog("WARN: rollback rename failed: %v, trying copy", err)
		// Fallback to copy if rename fails (e.g. cross-device)
		if err := copyFile(backupPath, binaryPath); err != nil {
			wlog("ERROR: rollback copy also failed: %v", err)
		}
	}
	setExecutable(binaryPath)
	if err := startService(); err != nil {
		wlog("ERROR: rollback start failed: %v", err)
	}
	wlog("Rollback complete")
}

// watcherCleanup removes the staging directory
func watcherCleanup(stagingDir string, wlog func(string, ...interface{})) {
	if err := os.RemoveAll(stagingDir); err != nil {
		wlog("WARN: cleanup staging failed: %v", err)
	} else {
		wlog("Cleanup done")
	}
}

// copyFile copies src to dst, creating/truncating dst with 0755 permissions
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("create dest %s: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

// openLogFile opens the log file for append, creating if necessary
func openLogFile(path string) *os.File {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return os.Stderr
	}
	return f
}
