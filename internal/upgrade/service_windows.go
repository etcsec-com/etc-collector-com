//go:build windows

package upgrade

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// windowsServiceName matches the SCM service installed by
// `etc-collector install` on Windows (cf. cmd/etc-collector/service_windows.go).
const windowsServiceName = "etcsec-collector"

type windowsController struct {
	name string
}

func newServiceController() ServiceController {
	return &windowsController{name: windowsServiceName}
}

func (c *windowsController) Name() string { return c.name }

// open connects to SCM and returns the service handle. Caller closes both.
func (c *windowsController) open() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("connect SCM: %w", err)
	}
	s, err := m.OpenService(c.name)
	if err != nil {
		m.Disconnect()
		return nil, nil, fmt.Errorf("open service %s: %w", c.name, err)
	}
	return m, s, nil
}

func (c *windowsController) IsInstalled() bool {
	m, s, err := c.open()
	if err != nil {
		return false
	}
	s.Close()
	m.Disconnect()
	return true
}

func (c *windowsController) IsActive() (bool, error) {
	m, s, err := c.open()
	if err != nil {
		return false, nil
	}
	defer m.Disconnect()
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return false, fmt.Errorf("query: %w", err)
	}
	return st.State == svc.Running, nil
}

func (c *windowsController) Stop(timeout time.Duration) error {
	m, s, err := c.open()
	if err != nil {
		// Service not installed — soft success (matches Unix behavior).
		return nil
	}
	defer m.Disconnect()
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	if st.State == svc.Stopped {
		return nil
	}

	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("send stop: %w", err)
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err = s.Query()
		if err != nil {
			return fmt.Errorf("query during stop: %w", err)
		}
		if st.State == svc.Stopped {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not stop within %s", timeout)
}

func (c *windowsController) Start(timeout time.Duration) error {
	m, s, err := c.open()
	if err != nil {
		return nil // not installed → no-op
	}
	defer m.Disconnect()
	defer s.Close()

	if err := s.Start(); err != nil {
		// "An instance of the service is already running" is fine.
		return fmt.Errorf("start: %w", err)
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("query during start: %w", err)
		}
		if st.State == svc.Running {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not start within %s", timeout)
}
