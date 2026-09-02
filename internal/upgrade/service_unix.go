//go:build !windows

package upgrade

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// linuxServiceName matches the unit installed by `etc-collector install`
// (cf. cmd/etc-collector/install.go:linuxServiceFile).
const linuxServiceName = "etcsec-collector"

// darwinPlistLabel matches the launchd Label installed by
// `etc-collector install` on macOS (cf. install.go:darwinPlistFile).
const darwinPlistLabel = "com.etcsec.collector"

// unixController routes to the correct service manager for the OS. We pick
// systemctl on Linux and launchctl on Darwin. Anything else (Alpine OpenRC,
// FreeBSD, ...) falls through to a "not installed" state and the upgrade
// runs in no-restart mode automatically.
type unixController struct {
	kind string // "systemd" | "launchd" | "none"
	name string
}

func newServiceController() ServiceController {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("systemctl"); err == nil {
			return &unixController{kind: "systemd", name: linuxServiceName}
		}
	case "darwin":
		if _, err := exec.LookPath("launchctl"); err == nil {
			return &unixController{kind: "launchd", name: darwinPlistLabel}
		}
	}
	return &unixController{kind: "none", name: ""}
}

func (c *unixController) Name() string { return c.name }

// IsInstalled checks the service manager has a registration for our unit.
// The exact command varies per kind. We treat "not found" / non-zero exit
// as "not installed" — callers fall back to no-restart mode.
func (c *unixController) IsInstalled() bool {
	switch c.kind {
	case "systemd":
		// `systemctl cat <unit>` exits 0 only if the unit file exists.
		out, err := exec.Command("systemctl", "cat", c.name).CombinedOutput()
		_ = out
		return err == nil
	case "launchd":
		// launchctl list <label> exits 0 if loaded.
		err := exec.Command("launchctl", "list", c.name).Run()
		return err == nil
	}
	return false
}

func (c *unixController) IsActive() (bool, error) {
	switch c.kind {
	case "systemd":
		out, _ := exec.Command("systemctl", "is-active", c.name).Output()
		return strings.TrimSpace(string(out)) == "active", nil
	case "launchd":
		// `launchctl list <label>` returns 0 = loaded; we can't easily tell
		// "loaded but not running" without parsing — treat loaded as active
		// for the upgrade workflow (we only call IsActive after Start).
		err := exec.Command("launchctl", "list", c.name).Run()
		return err == nil, nil
	}
	return false, nil
}

func (c *unixController) Stop(timeout time.Duration) error {
	if c.kind == "none" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	switch c.kind {
	case "systemd":
		cmd = exec.CommandContext(ctx, "systemctl", "stop", c.name)
	case "launchd":
		// Prefer `launchctl bootout` when the label is loaded under system
		// domain; fall back to `unload` for older macOS.
		cmd = exec.CommandContext(ctx, "launchctl", "bootout", "system/"+c.name)
	}
	if cmd == nil {
		return nil
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		// On launchd, "service not loaded" is a soft failure — treat as success.
		if c.kind == "launchd" && strings.Contains(string(out), "could not find") {
			return nil
		}
		return fmt.Errorf("%s: %v: %s", strings.Join(cmd.Args, " "), err, string(out))
	}

	// Wait until is-active turns false (some service managers return immediately).
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		active, _ := c.IsActive()
		if !active {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("service did not stop within %s", timeout)
}

func (c *unixController) Start(timeout time.Duration) error {
	if c.kind == "none" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	switch c.kind {
	case "systemd":
		cmd = exec.CommandContext(ctx, "systemctl", "start", c.name)
	case "launchd":
		cmd = exec.CommandContext(ctx, "launchctl", "bootstrap", "system",
			"/Library/LaunchDaemons/"+c.name+".plist")
	}
	if cmd == nil {
		return nil
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(cmd.Args, " "), err, string(out))
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		active, _ := c.IsActive()
		if active {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not become active within %s", timeout)
}
