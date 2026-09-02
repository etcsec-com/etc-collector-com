//go:build !windows

package saas

import (
	"os"
	"path/filepath"
	"strings"
)

// warnIfLegacyLayout logs a warning when the running daemon binary lives in
// /usr/local/bin (the pre-3.0.23 layout). On systemd, this layout breaks
// UPDATE_COLLECTOR because /usr/local/bin is outside ReadWritePaths.
//
// The fix is `sudo etc-collector install --upgrade`. Logged once at startup —
// not fatal, the daemon keeps running.
func (d *Daemon) warnIfLegacyLayout() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return
	}
	// New layout: real binary lives somewhere under DATA_DIR (e.g.
	// /var/lib/etc-collector/bin). Anything under /usr/local/bin is legacy.
	if strings.HasPrefix(resolved, "/usr/local/bin/") {
		d.logger.Warn(
			"Legacy install layout detected — UPDATE_COLLECTOR will likely fail "+
				"under systemd hardening. Run 'sudo etc-collector install --upgrade' "+
				"to migrate the binary to the writable layout.",
			"binaryPath", resolved,
		)
	}
}
