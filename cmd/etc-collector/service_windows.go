//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/etcsec-com/etc-collector/internal/api"
	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/guitoken"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/internal/providers/ldap"
	"github.com/etcsec-com/etc-collector/internal/saas"

	// Import detectors to register them via init()
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad"
)

// windowsServiceLegacyName was this file's own service identity before
// B_184 (T_089): "ETCCollector" — a second, divergent Windows service name
// from what `etc-collector install` creates (install_windows.go's
// installServiceName, "EtcSecCollector"). installWindowsService no longer
// creates a service under this name; kept only so uninstallService can
// clean up an entry a prior binary version may have left behind.
const windowsServiceLegacyName = "ETCCollector"

var elog debug.Log

// windowsService implements svc.Handler
type windowsService struct {
	server *api.Server
	cancel context.CancelFunc
}

func (ws *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}
	elog.Info(1, fmt.Sprintf("Starting %s service", installServiceName))

	// Load configuration
	exePath, _ := os.Executable()
	workDir := filepath.Dir(exePath)
	os.Chdir(workDir)

	cfg, err := config.Load(filepath.Join(workDir, "config.yaml"))
	if err != nil {
		cfg = config.Default()
		elog.Warning(1, fmt.Sprintf("Using default config: %v", err))
	}

	// B_084 (T_067): same defect as the foreground `server` command (server.go) —
	// cfg.LoadKeys() only ever reads existing key files, never generates them, so a
	// fresh install had no private key and every POST /api/v1/auth/token failed.
	// saas.EnsureJWTKeys is the same on-demand generator daemon mode already uses.
	keysDir := filepath.Join(workDir, "keys")
	cfg.Auth.JWTPrivateKeyPath = filepath.Join(keysDir, "private.pem")
	cfg.Auth.JWTPublicKeyPath = filepath.Join(keysDir, "public.pem")
	if err := saas.EnsureJWTKeys(keysDir); err != nil {
		elog.Warning(1, fmt.Sprintf("Failed to generate JWT keys: %v", err))
	}
	if err := cfg.LoadKeys(); err != nil {
		elog.Warning(1, fmt.Sprintf("Failed to load JWT keys: %v", err))
	}

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	ws.cancel = cancel

	// Initialize LDAP provider — optional. B_184 (T_089): this used to treat a
	// missing or unreachable LDAP config as FATAL (elog.Error + return true, 1),
	// unlike runServer's own CLI path (server.go), which has always logged "No
	// LDAP configured — configure via GUI" and started anyway. That divergence
	// was low-impact while this Execute was only reachable via the obscure,
	// divergent `service run` command; now that runServer's own SCM path
	// (runServerAsWindowsService) reuses it, a fresh Windows install with no
	// LDAP configured yet would otherwise NEVER start the service at all — a
	// chicken-and-egg lockout, since LDAP is normally configured THROUGH the
	// admin GUI this service is supposed to expose. Confirmed live on DC01:
	// exactly this fatal exit (WIN32_EXIT_CODE 1066), event log "Failed to
	// create LDAP client: LDAP URL is required", on an intentionally
	// unconfigured test instance.
	manager := providers.NewManager()
	if cfg.LDAP.URL == "" {
		elog.Info(1, "No LDAP configured — configure via the admin GUI")
	} else if ldapProvider, err := ldap.NewClient(ldap.Config{
		URL:           cfg.LDAP.URL,
		BindDN:        cfg.LDAP.BindDN,
		BindPassword:  cfg.LDAP.BindPassword,
		BaseDN:        cfg.LDAP.BaseDN,
		TLSVerify:     cfg.LDAP.TLSVerify,
		TLSCACert:     cfg.LDAP.TLSCACert,
		TLSCACertPEM:  cfg.LDAP.TLSCACertPEM,
		TLSMinVersion: cfg.LDAP.TLSMinVersion,
		StartTLS:      cfg.LDAP.StartTLS,
		Timeout:       cfg.LDAP.Timeout,
	}); err != nil {
		elog.Warning(1, fmt.Sprintf("Failed to create LDAP client, starting without LDAP: %v", err))
	} else if err := ldapProvider.Connect(ctx); err != nil {
		elog.Warning(1, fmt.Sprintf("Failed to connect to LDAP, starting without LDAP: %v", err))
	} else {
		elog.Info(1, "LDAP connection successful")
		manager.Register(ldapProvider)
	}

	// Create and start API server
	ws.server = api.NewServer(cfg, manager)

	// Load (or generate) GUI access token hash. T_041/B_040: the admin API is
	// fail-closed with no hash configured, so ensure one exists before Start() can
	// accept a request — an upgraded-not-reinstalled install would otherwise be
	// locked out of its own admin API.
	if hash, token, generated, err := guitoken.EnsureHash(windowsDataDir); err != nil {
		elog.Error(1, fmt.Sprintf("Failed to ensure GUI access token: %v", err))
	} else {
		ws.server.SetGuiTokenHash(hash)
		if generated {
			// B_135 (T_060): the token itself must never reach the event log — see
			// guitoken.AnnounceFirstRun for where it actually goes.
			elog.Warning(1, "No GUI access token was configured — generated one now. "+
				"See <configDir>/gui-token.firstrun for the token (reset with 'etc-collector gui-token reset').")
			if err := guitoken.AnnounceFirstRun(windowsDataDir, token); err != nil {
				elog.Error(1, fmt.Sprintf("Failed to write gui-token.firstrun: %v", err))
			}
		}
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- ws.server.Start()
	}()

	// Wait for server to start
	time.Sleep(time.Second)

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	elog.Info(1, fmt.Sprintf("%s service is now running on port %d", installServiceName, cfg.Server.Port))

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				elog.Info(1, fmt.Sprintf("Stopping %s service", installServiceName))
				break loop
			default:
				elog.Warning(1, fmt.Sprintf("Unexpected control request #%d", c))
			}
		case err := <-errCh:
			if err != nil {
				elog.Error(1, fmt.Sprintf("Server error: %v", err))
			}
			break loop
		}
	}

	changes <- svc.Status{State: svc.StopPending}

	// Shutdown server
	if ws.server != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		ws.server.Shutdown(shutdownCtx)
	}
	if ws.cancel != nil {
		ws.cancel()
	}

	elog.Info(1, fmt.Sprintf("%s service stopped", installServiceName))
	return
}

// runService runs as a Windows service. Kept for `etc-collector service run`
// (B_184, T_089: backward compatibility only — any SCM entry a prior binary
// version created with this as its ImagePath must keep working after an
// upgrade). New installs never point here; both `install --mode server` and
// `service install` create a service that runs `server` directly, handled
// by runServerAsWindowsService below — the same underlying mechanism.
func runService(isDebug bool) error {
	if isDebug {
		elog = debug.New(installServiceName)
		defer elog.Close()
		elog.Info(1, fmt.Sprintf("Starting %s service", installServiceName))
		if err := debug.Run(installServiceName, &windowsService{}); err != nil {
			elog.Error(1, fmt.Sprintf("%s service failed: %v", installServiceName, err))
			return err
		}
		elog.Info(1, fmt.Sprintf("%s service stopped", installServiceName))
		return nil
	}
	return runServerAsWindowsService()
}

// runServerAsWindowsService runs server mode under Windows SCM control.
//
// B_184 (T_089): `etc-collector server` had NO Windows SCM integration at
// all — install_windows.go's installWindowsSCMService(mode="server") points
// a service's ImagePath at `<bin> server` directly, and nothing in
// runServer (server.go) ever called svc.Run to report status back to the
// Service Control Manager. Confirmed live on DC01 with a throwaway test
// service: `sc start` failed with error 1053 ("did not respond ... in a
// timely fashion") on the exact binary that serves requests fine when run
// any other way — the gap was specifically the missing SCM handshake.
// windowsService.Execute already implements this handshake correctly (same
// shape as daemon_windows.go's daemonService.Execute) — this just gives it
// one canonical name and makes it reachable from server.go's own RunE, not
// only from the now-legacy `service run` subcommand.
func runServerAsWindowsService() error {
	var err error
	elog, err = eventlog.Open(installServiceName)
	if err != nil {
		return fmt.Errorf("open event log: %w", err)
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("Starting %s service", installServiceName))
	if err := svc.Run(installServiceName, &windowsService{}); err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", installServiceName, err))
		return err
	}
	elog.Info(1, fmt.Sprintf("%s service stopped", installServiceName))
	return nil
}

// installWindowsService installs the Windows service with configuration
func installWindowsService() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Create config file in the same directory as the executable
	workDir := filepath.Dir(exePath)
	configPath := filepath.Join(workDir, "config.yaml")

	// Create config content
	configContent := fmt.Sprintf(`# ETC Collector Configuration
# Generated by service install

server:
  port: %d
  host: "0.0.0.0"

ldap:
  url: "%s"
  bindDN: "%s"
  bindPassword: "%s"
  baseDN: "%s"
  tlsVerify: %t
  timeout: 30s

auth:
  jwtPrivateKeyPath: "./keys/private.pem"
  jwtPublicKeyPath: "./keys/public.pem"
  tokenLifetime: 720h

log:
  level: "info"
  format: "json"
`, svcPort, svcLdapURL, svcLdapBindDN, svcLdapBindPass, svcLdapBaseDN, !svcLdapTLSSkip)

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	fmt.Printf("Configuration written to: %s\n", configPath)

	// B_184 (T_089): this used to hand-roll its own mgr.CreateService call —
	// same SCM API, but under the divergent name "ETCCollector" and with an
	// ImagePath of `<bin> service run`. Delegates to the exact same function
	// `etc-collector install --mode server` uses (install_windows.go), so
	// both paths create one service, "EtcSecCollector", with ImagePath
	// `<bin> server` — now correctly SCM-integrated via
	// runServerAsWindowsService above.
	if err := installWindowsSCMService(exePath, "server"); err != nil {
		return err
	}

	fmt.Printf("\nService '%s' installed successfully!\n", installServiceName)
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Ensure JWT keys exist in the 'keys' folder")
	fmt.Println("  2. Start the service: etc-collector service start")
	fmt.Println("  3. Check status: etc-collector service status")
	return nil
}

// uninstallService removes the Windows service.
//
// B_184 (T_089): also best-effort removes a service under
// windowsServiceLegacyName ("ETCCollector") if one exists — a prior binary
// version could have created it via the old, divergent installWindowsService,
// and nothing else will ever clean it up now that installation converges on
// installServiceName. A ghost SCM entry surviving reinstall/reboot is
// exactly the failure mode this ticket exists to close.
func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	removeService(m, installServiceName)
	removeService(m, windowsServiceLegacyName)

	fmt.Printf("Service '%s' removed successfully\n", installServiceName)
	return nil
}

// removeService stops (if running) and deletes the named service, and its
// event log source, if it exists. Absence is not an error — callers use
// this for best-effort legacy cleanup as well as the primary uninstall.
func removeService(m *mgr.Mgr, name string) {
	s, err := m.OpenService(name)
	if err != nil {
		return // not installed under this name — nothing to do
	}
	defer s.Close()

	if status, err := s.Query(); err == nil && status.State != svc.Stopped {
		s.Control(svc.Stop)
		for i := 0; i < 10; i++ {
			time.Sleep(time.Second)
			status, err := s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
		}
	}

	if err := s.Delete(); err != nil {
		fmt.Printf("Warning: failed to delete service %s: %v\n", name, err)
		return
	}
	if err := eventlog.Remove(name); err != nil {
		fmt.Printf("Warning: failed to remove event log for %s: %v\n", name, err)
	}
}

// startWindowsService starts the Windows service
func startWindowsService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(installServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", installServiceName)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("Service '%s' started\n", installServiceName)
	return nil
}

// stopWindowsService stops the Windows service
func stopWindowsService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(installServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", installServiceName)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	// Wait for service to stop
	timeout := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(timeout) {
			return fmt.Errorf("timeout waiting for service to stop")
		}
		time.Sleep(time.Second)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("failed to query service: %w", err)
		}
	}

	fmt.Printf("Service '%s' stopped\n", installServiceName)
	return nil
}

// statusWindowsService shows the status of the Windows service
func statusWindowsService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(installServiceName)
	if err != nil {
		fmt.Printf("Service '%s' is not installed\n", installServiceName)
		return nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("failed to query service: %w", err)
	}

	stateStr := "Unknown"
	switch status.State {
	case svc.Stopped:
		stateStr = "Stopped"
	case svc.StartPending:
		stateStr = "Starting"
	case svc.StopPending:
		stateStr = "Stopping"
	case svc.Running:
		stateStr = "Running"
	case svc.ContinuePending:
		stateStr = "Continue Pending"
	case svc.PausePending:
		stateStr = "Pause Pending"
	case svc.Paused:
		stateStr = "Paused"
	}

	fmt.Printf("Service: %s\n", installServiceName)
	fmt.Printf("Status:  %s\n", stateStr)
	fmt.Printf("PID:     %d\n", status.ProcessId)
	return nil
}

// isWindowsService checks if running as a Windows service
func isWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}
