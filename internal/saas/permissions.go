package saas

import (
	"fmt"
	"os"
)

// Permissions for the on-disk state the collector owns. The collector runs as
// root/SYSTEM on a customer domain controller, so everything it writes is
// owner-only: nothing here needs to be readable by another local account.
const (
	// SecureDirMode — config and data directories. 0700, not 0755: the files
	// inside are already 0600, but a 0755 directory still lets any local user
	// enumerate what a security product keeps on that host.
	SecureDirMode os.FileMode = 0700

	// SecureFileMode — credentials, tokens, logs.
	SecureFileMode os.FileMode = 0600
)

// SecureDir creates dir with mode and — crucially — tightens it when it ALREADY
// EXISTS with looser permissions.
//
// A_004 K7(b): os.MkdirAll's mode argument only applies to directories it actually
// creates. Every collector installed before this change has its config directory at
// 0755, so simply changing the MkdirAll argument would have fixed new installs and
// left the entire existing fleet untouched, forever. The explicit Chmod is the part
// that matters.
//
// On Windows this is best-effort: Go's os.Chmod only toggles the read-only attribute
// and cannot express an ACL, so directory protection there comes from the parent
// (C:\ProgramData\ETCSec) rather than from this call. Stated plainly rather than
// papered over — see the delivery.
func SecureDir(dir string) error {
	if err := os.MkdirAll(dir, SecureDirMode); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, SecureDirMode); err != nil {
		return fmt.Errorf("tighten permissions on %s: %w", dir, err)
	}
	return nil
}

// SecureFile tightens an existing file to owner-only. Same reasoning as SecureDir:
// os.WriteFile's mode applies only when it creates the file, so a file left behind by
// an older version keeps its original mode until something explicitly chmods it.
// Missing files are not an error — there is nothing to protect yet.
func SecureFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if err := os.Chmod(path, SecureFileMode); err != nil {
		return fmt.Errorf("tighten permissions on %s: %w", path, err)
	}
	return nil
}
