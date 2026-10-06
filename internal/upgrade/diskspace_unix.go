//go:build !windows

package upgrade

import "syscall"

// freeBytes returns available bytes on the filesystem hosting path.
// Used by preflightDisk to fail fast on full disks (the dock-04 case
// where the upgrade aborted halfway through and left the host stuck).
func freeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}
