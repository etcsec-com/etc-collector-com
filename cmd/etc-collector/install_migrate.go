package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/etcsec-com/etc-collector/internal/saas"
)

// runInstallUpgrade migrates an existing install to the v3.0.23+ layout.
//
// Idempotent: if the layout is already correct it just rewrites the systemd
// unit (cheap) and exits.
//
// Steps:
//  1. Detect legacy real binary at /usr/local/bin/etc-collector
//  2. Move it to /var/lib/etc-collector/bin/etc-collector (real binary)
//  3. Replace /usr/local/bin/etc-collector with a symlink to the new path
//  4. Rewrite the systemd unit so ExecStart points to the writable path
//  5. systemctl daemon-reload + restart etcsec-collector
//
// Windows: not applicable (no symlink dance, no systemd, no cgroup-kill bug).
func runInstallUpgrade() error {
	if runtime.GOOS == "windows" {
		fmt.Println("--upgrade is a Unix-only migration; nothing to do on Windows.")
		return nil
	}

	cfgDir, _, binDir := resolvePlatformPaths()
	if installConfigDirFlag != "" {
		cfgDir = installConfigDirFlag
	}
	symPath := platformSymlinkPath()
	realBinary := filepath.Join(binDir, binaryName())

	fmt.Println("Migrating ETC Collector to v3.0.23+ layout...")
	fmt.Printf("  Real binary target:  %s\n", realBinary)
	fmt.Printf("  Symlink:             %s\n", symPath)

	// B_042/T_041: tighten the config directory too — this is the other realistic
	// trigger point (besides a daemon restart) where an existing 0755 install
	// actually re-runs this code, and CredentialStore.Save() alone never reaches an
	// install that isn't currently writing credentials.
	if err := saas.SecureDir(cfgDir); err != nil {
		return fmt.Errorf("secure config directory %s: %w", cfgDir, err)
	}
	fmt.Println("  [OK] Config directory permissions verified")

	// Ensure the destination dir exists.
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", binDir, err)
	}

	// Inspect what's at symPath today.
	info, err := os.Lstat(symPath)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		// Already a symlink. Check it points where we expect.
		current, _ := os.Readlink(symPath)
		if current == realBinary {
			fmt.Println("  [OK] Symlink already points to the new layout.")
		} else {
			fmt.Printf("  [WARN] Symlink points elsewhere (%s); recreating.\n", current)
			if err := ensureSymlink(realBinary, symPath); err != nil {
				return err
			}
		}
		// Make sure the real binary actually exists.
		if _, err := os.Stat(realBinary); os.IsNotExist(err) {
			fmt.Printf("  [WARN] Symlink points to %s but the file is missing. Reinstall manually.\n", realBinary)
		}

	case err == nil && info.Mode().IsRegular():
		// Legacy layout: real file in /usr/local/bin. Move it.
		fmt.Printf("  Detected legacy install at %s, migrating...\n", symPath)
		// Pre-clean any stale destination so the rename won't fail because of permissions.
		_ = os.Remove(realBinary)
		if err := os.Rename(symPath, realBinary); err != nil {
			// Fallback to copy (e.g. if /usr/local/bin and /var/lib are on different filesystems).
			if cerr := atomicCopyFile(symPath, realBinary); cerr != nil {
				return fmt.Errorf("move binary: rename failed (%v) and copy fallback failed: %w", err, cerr)
			}
			_ = os.Remove(symPath)
		}
		if err := os.Chmod(realBinary, 0755); err != nil {
			return fmt.Errorf("chmod %s: %w", realBinary, err)
		}
		if err := ensureSymlink(realBinary, symPath); err != nil {
			return err
		}
		fmt.Println("  [OK] Binary moved + symlink created")

	case os.IsNotExist(err):
		// Nothing in /usr/local/bin yet. Need a real binary to point at.
		// Use the currently running executable as the source.
		srcPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("--upgrade: no install detected and cannot locate self: %w", err)
		}
		srcPath, _ = filepath.EvalSymlinks(srcPath)
		fmt.Printf("  No existing install at %s, copying current binary from %s\n", symPath, srcPath)
		if err := atomicCopyFile(srcPath, realBinary); err != nil {
			return err
		}
		if err := ensureSymlink(realBinary, symPath); err != nil {
			return err
		}
		fmt.Println("  [OK] Binary installed + symlink created")

	default:
		return fmt.Errorf("unexpected state at %s: %w", symPath, err)
	}

	// Rewrite the service unit so ExecStart points to the real binary path.
	if err := installService(realBinary, cfgDir, detectInstalledMode(cfgDir)); err != nil {
		return fmt.Errorf("rewrite service unit: %w", err)
	}
	fmt.Println("  [OK] Service unit rewritten")

	// On Linux, reload systemd and restart the service so the new ExecStart takes effect.
	if runtime.GOOS == "linux" {
		if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %w", err)
		}
		if err := exec.Command("systemctl", "restart", "etcsec-collector").Run(); err != nil {
			fmt.Printf("  [WARN] systemctl restart failed: %v (run manually)\n", err)
		} else {
			fmt.Println("  [OK] Service restarted with new layout")
		}
	}

	fmt.Println()
	fmt.Println("Migration complete. Future UPDATE_COLLECTOR commands will use in-place exec.")
	return nil
}

// detectInstalledMode peeks at credentials.json to decide if the unit was
// installed in 'saas' or 'server' mode. Defaults to 'saas' which is the most
// common managed deployment.
func detectInstalledMode(cfgDir string) string {
	if _, err := os.Stat(filepath.Join(cfgDir, "credentials.json")); err == nil {
		return "saas"
	}
	return "server"
}
