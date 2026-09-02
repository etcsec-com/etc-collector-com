//go:build windows

package saas

// warnIfLegacyLayout is a no-op on Windows: there's no symlink dance and
// UPDATE_COLLECTOR uses the watcher pattern (not affected by the systemd
// cgroup-kill bug).
func (d *Daemon) warnIfLegacyLayout() {}
