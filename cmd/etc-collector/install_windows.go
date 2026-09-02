//go:build windows

package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	installServiceName    = "EtcSecCollector"
	installServiceDisplay = "ETC Security Collector"
	installServiceDesc    = "Identity security audit collector for Active Directory and cloud environments"
)

// installWindowsSCMService installs a Windows service via SCM
func installWindowsSCMService(binPath, mode string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Check if service already exists
	s, err := m.OpenService(installServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists. Run 'uninstall' first", installServiceName)
	}

	// Determine service arguments based on mode
	serviceArgs := []string{"daemon"}
	if mode == "server" {
		serviceArgs = []string{"server"}
	}

	s, err = m.CreateService(installServiceName, binPath, mgr.Config{
		DisplayName: installServiceDisplay,
		Description: installServiceDesc,
		StartType:   mgr.StartAutomatic,
	}, serviceArgs...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	err = eventlog.InstallAsEventCreate(installServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		return fmt.Errorf("install event log: %w", err)
	}

	return nil
}

// startWindowsSCMService starts the Windows service
func startWindowsSCMService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(installServiceName)
	if err != nil {
		return fmt.Errorf("service not installed: %w", err)
	}
	defer s.Close()

	return s.Start()
}

// stopWindowsSCMService stops the Windows service
func stopWindowsSCMService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(installServiceName)
	if err != nil {
		return fmt.Errorf("service not installed: %w", err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}

	timeout := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(timeout) {
			return fmt.Errorf("timeout waiting for service to stop")
		}
		time.Sleep(time.Second)
		status, err = s.Query()
		if err != nil {
			return err
		}
	}

	return nil
}

// removeWindowsSCMService removes the Windows service
func removeWindowsSCMService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(installServiceName)
	if err != nil {
		return nil // Not installed, nothing to do
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	eventlog.Remove(installServiceName)
	return nil
}
