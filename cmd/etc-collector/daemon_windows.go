//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/etcsec-com/etc-collector/internal/saas"
)

// daemonService implements svc.Handler for daemon mode (SaaS)
type daemonService struct {
	daemon *saas.Daemon
}

func (ds *daemonService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	if err := ds.daemon.Start(); err != nil {
		return true, 1
	}

	// Start embedded GUI in Windows service mode
	if guiPort > 0 {
		if err := ds.daemon.StartEmbeddedGUI(guiHost, guiPort); err != nil {
			return true, 1
		}
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			ds.daemon.Stop()
			return
		}
	}
}

// isWindowsServiceContext returns true if running inside Windows SCM
func isWindowsServiceContext() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}

// runDaemonAsWindowsService runs the daemon under Windows SCM control
func runDaemonAsWindowsService(daemon *saas.Daemon) error {
	elog, err := eventlog.Open(installServiceName)
	if err != nil {
		return fmt.Errorf("open event log: %w", err)
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("Starting %s daemon service", installServiceName))

	err = svc.Run(installServiceName, &daemonService{daemon: daemon})
	if err != nil {
		elog.Error(1, fmt.Sprintf("Daemon service failed: %v", err))
		return err
	}

	elog.Info(1, fmt.Sprintf("%s daemon service stopped", installServiceName))
	return nil
}
