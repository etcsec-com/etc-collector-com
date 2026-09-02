package upgrade

import "time"

// ServiceController abstracts the platform-specific service manager so the
// rest of the upgrade flow stays OS-agnostic. Implementations live in
// service_unix.go (systemd / launchd) and service_windows.go (SCM).
//
// All methods are best-effort and tolerant of missing services: a host that
// installed the binary manually (no systemd unit) should still be able to
// `etc-collector upgrade` — the controller reports IsInstalled() == false
// and the caller skips Stop/Start.
type ServiceController interface {
	// Name returns a human-readable identifier ("etcsec-collector",
	// "com.etcsec.collector", ...). Used in user-facing log lines.
	Name() string

	// IsInstalled reports whether the service unit/plist/SCM entry exists
	// on this host. False = upgrade in --no-restart mode (caller's choice).
	IsInstalled() bool

	// IsActive reports whether the service is currently running.
	IsActive() (bool, error)

	// Stop blocks until the service is fully stopped or the timeout expires.
	// Returns nil if the service is already stopped.
	Stop(timeout time.Duration) error

	// Start blocks until the service reports active or the timeout expires.
	Start(timeout time.Duration) error
}

// NewServiceController returns the platform default. The returned controller
// is safe to use even if the service is not installed — IsInstalled() reports
// the actual state and Stop/Start no-op when nothing is registered.
func NewServiceController() ServiceController {
	return newServiceController()
}
