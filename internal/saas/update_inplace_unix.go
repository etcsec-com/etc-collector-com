//go:build !windows

package saas

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// swapBinaryOnly performs the atomic on-disk binary swap (steps 1-4 of the
// in-place update). It must complete BEFORE any cleanup of the staging
// directory and BEFORE submitSuccess is sent to the SaaS — otherwise the
// staged file may disappear before rename() can run.
//
// Returns the backup path so the caller can rollback if syscall.Exec later
// fails. On success the new binary is at currentBinary, the old one at backup.
//
// Works because:
//   - On Unix, rename() over an executing binary is allowed (the kernel keeps
//     the old inode mapped for the running process; new PIDs see the new file).
//   - rename() inside the same directory is atomic and survives crashes.
func swapBinaryOnly(currentBinary, newBinary string) (string, error) {
	backup := currentBinary + ".bak"

	// 1. Remove any stale backup (best-effort).
	_ = os.Remove(backup)

	// 2. Backup the current binary by renaming it to .bak.
	//    This works even though the file is currently executing.
	if err := os.Rename(currentBinary, backup); err != nil {
		return "", fmt.Errorf("backup current binary: %w", err)
	}

	// 3. Move the staged new binary into place. Fall back to copy+unlink on
	//    EXDEV: under systemd ProtectSystem=strict + multiple ReadWritePaths,
	//    each path is a distinct bind-mount in the service's namespace and
	//    rename() across mounts returns EXDEV even though the physical FS is
	//    identical. v3.1.7+ stages next to the target binary to avoid this
	//    entirely — this is defense in depth for custom layouts.
	if err := installBinary(newBinary, currentBinary); err != nil {
		// Rollback: restore the backup.
		if rerr := os.Rename(backup, currentBinary); rerr != nil {
			return "", fmt.Errorf("install new binary: %w (rollback also failed: %v)", err, rerr)
		}
		return "", fmt.Errorf("install new binary (rolled back): %w", err)
	}

	// 4. Make sure the new file is executable. Should already be 0755 from
	//    the extract step, but enforce.
	if err := os.Chmod(currentBinary, 0755); err != nil {
		// Try to roll back so we don't leave a non-executable binary in place.
		if rerr := rollbackBinary(currentBinary, backup); rerr != nil {
			return "", fmt.Errorf("chmod new binary: %w (rollback failed: %v)", err, rerr)
		}
		return "", fmt.Errorf("chmod new binary (rolled back): %w", err)
	}

	return backup, nil
}

// execInPlace replaces the current process image with the new binary at
// currentBinary. backup is used to rollback if exec() itself fails.
//
// This function does not return on success — syscall.Exec replaces the
// process image, keeping the same PID so systemd sees no exit event
// (no KillMode trigger, no Restart=always counter increment).
//
// Failure here is rare (corrupt binary, EPERM, ENOEXEC). The caller should
// log the error and exit so systemd restarts on the new on-disk binary.
func execInPlace(currentBinary, backup string) error {
	// Brief flush window — give the kernel a moment to fsync the rename
	//   and let any in-flight HTTP response close cleanly.
	time.Sleep(200 * time.Millisecond)

	args := os.Args
	if len(args) == 0 {
		args = []string{currentBinary}
	}
	if err := syscall.Exec(currentBinary, args, os.Environ()); err != nil {
		if rerr := rollbackBinary(currentBinary, backup); rerr != nil {
			return fmt.Errorf("syscall.Exec: %w (rollback failed: %v)", err, rerr)
		}
		return fmt.Errorf("syscall.Exec (rolled back): %w", err)
	}
	// Unreachable on success.
	return nil
}

// installBinary renames src to dst, falling back to copy+unlink if the rename
// fails with EXDEV (cross-device link). The copy path writes to dst+".tmp"
// first then atomically renames into place so a crash during the copy can't
// leave a half-written binary at dst.
func installBinary(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if !isCrossDevice(err) {
		return err
	}
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	if err := copyFileContents(src, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("copy across devices: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename .tmp into place: %w", err)
	}
	_ = os.Remove(src) // best-effort cleanup of the staged copy
	return nil
}

// isCrossDevice reports whether err is the Linux EXDEV "invalid cross-device
// link" error returned by rename(2) when source and destination live on
// different filesystems (or different bind-mounts in a namespace).
func isCrossDevice(err error) bool {
	if errors.Is(err, syscall.EXDEV) {
		return true
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return errors.Is(linkErr.Err, syscall.EXDEV)
	}
	return false
}

// copyFileContents streams src to dst preserving executable permissions.
// The destination file is truncated on each call.
func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0755
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// rollbackBinary restores a backup over the current binary.
func rollbackBinary(currentBinary, backup string) error {
	_ = os.Remove(currentBinary)
	if err := os.Rename(backup, currentBinary); err != nil {
		return fmt.Errorf("rename backup back: %w", err)
	}
	if err := os.Chmod(currentBinary, 0755); err != nil {
		return fmt.Errorf("chmod restored binary: %w", err)
	}
	return nil
}

// preExecCleanup removes runtime markers that should not survive into the new
// process image (PID file is the critical one — the new process would think
// it's recovering from a crash if the file still pointed at the old PID).
//
// Called from executeUpdate just before swapAndExecInPlace.
func (d *Daemon) preExecCleanup(stagingDir string) {
	d.removePIDFile()
	if err := d.writeCleanShutdown(); err != nil {
		d.logger.Warn("preExecCleanup: writeCleanShutdown failed", "error", err)
	}
	// Cleanup staging — the new binary is already in place, we don't need
	// the staged copy anymore. Keep the staging dir itself for next time.
	_ = filepath.Walk(stagingDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && p != stagingDir && info != nil && !info.IsDir() {
			os.Remove(p)
		}
		return nil
	})
}

// awaitContextDone blocks until ctx is done or for at most d. Used to leave a
// tiny grace window for in-flight HTTP responses to flush before exec.
func awaitContextDone(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// performBinarySwap is the Unix entry point for the post-staging swap.
// Performs the on-disk swap synchronously, submits success, cleans up,
// then exec()s the new binary in place.
//
// Ordering is critical (was a bug v3.1.0–v3.1.12): the rename(staging → bin)
// must run BEFORE preExecCleanup (which deletes staging dir contents) and
// BEFORE submitSuccess (so we don't tell SaaS the update worked when it
// hasn't yet). The previous order caused crash-loops because preExecCleanup
// deleted the staged binary before swapAndExecInPlace could rename it.
//
// On systemd, the daemon process keeps the same PID across the swap, so the
// service unit sees no exit event and Restart=always doesn't fire.
//
// This function does not return on success.
func (d *Daemon) performBinarySwap(cmd Command, startedAt string, params *updateParams, binaryPath string, staged *stagedUpdate) {
	// 1. Swap the binary on disk FIRST.
	//    rename(staging → bin) MUST happen before staging cleanup or any
	//    success notification. If it fails, the old binary is restored and
	//    we report the error to SaaS.
	d.logger.Info("Swapping binary on disk",
		"commandId", cmd.CommandID,
		"binaryPath", binaryPath,
		"newBinaryPath", staged.NewBinaryPath,
		"targetVersion", params.targetVersion,
	)
	backup, err := swapBinaryOnly(binaryPath, staged.NewBinaryPath)
	if err != nil {
		d.logger.Error("Binary swap failed, keeping old version",
			"commandId", cmd.CommandID,
			"error", err,
		)
		d.submitError(cmd.CommandID, startedAt, "UPDATE_FAILED", "binary swap failed", err.Error())
		// Best-effort cleanup of the staging dir we never used.
		d.preExecCleanup(staged.StagingDir)
		return
	}

	// 2. NOW it is safe to submit success — the new binary is on disk in its
	//    final location. After syscall.Exec we have no chance to talk to the
	//    SaaS, so this MUST be done here.
	d.submitSuccess(cmd.CommandID, startedAt, map[string]string{
		"note":          "in-place exec (Unix)",
		"targetVersion": params.targetVersion,
		"method":        "syscall-exec",
	})

	// 3. Cleanup PID file, write clean shutdown marker, and remove the now-
	//    unused staging dir contents. Safe because the new binary is in
	//    binaryPath, not in stagingDir, anymore.
	d.preExecCleanup(staged.StagingDir)

	// 4. Signal background goroutines to exit. We do NOT wait for them —
	//    syscall.Exec will replace the process image and the kernel will tear
	//    down every goroutine + FD + socket with the old image. Calling the
	//    regular d.Stop() here deadlocks (we run inside commandLoop, which is
	//    tracked by the WaitGroup that Stop() wg.Wait()s on).
	d.logger.Info("Signaling daemon goroutines before in-place exec",
		"commandId", cmd.CommandID,
		"targetVersion", params.targetVersion,
	)
	d.stopForExec()

	// 5. Exec the new binary in place. On success this never returns.
	d.logger.Info("Performing in-place exec on new binary")
	if err := execInPlace(binaryPath, backup); err != nil {
		// exec() failed (corrupt binary, EPERM, ENOEXEC). The on-disk binary
		// has been rolled back to the old one in execInPlace. Exit so systemd
		// restarts the daemon on the previous (working) version.
		d.logger.Error("In-place exec failed, exiting so systemd restarts the old version",
			"error", err,
		)
		os.Exit(1)
	}
	// Unreachable.
}
