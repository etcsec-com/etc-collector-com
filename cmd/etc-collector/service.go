package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the ETC Collector service",
	Long: `Manage the ETC Collector as a system service.

On Windows, this installs/manages a Windows Service.
On Linux, this generates systemd unit files.

Examples:
  etc-collector service install --ldap-url ldaps://dc.example.com:636
  etc-collector service start
  etc-collector service stop
  etc-collector service status
  etc-collector service uninstall`,
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install ETC Collector as a system service",
	Long: `Install ETC Collector as a system service.

On Windows, this creates a Windows Service that starts automatically.
On Linux, this creates a systemd unit file.

The service will use the configuration from:
- Command line flags (stored in service config)
- Environment variables
- Config file (./config.yaml or /etc/etc-collector/config.yaml)`,
	RunE: runServiceInstall,
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the ETC Collector service",
	RunE:  runServiceUninstall,
}

var serviceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the ETC Collector service",
	RunE:  runServiceStart,
}

var serviceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the ETC Collector service",
	RunE:  runServiceStop,
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of the ETC Collector service",
	RunE:  runServiceStatus,
}

var serviceRunCmd = &cobra.Command{
	Use:    "run",
	Short:  "Run the service (called by service manager)",
	Hidden: true, // Hidden as it's called by Windows Service Manager
	RunE:   runServiceRun,
}

// Service configuration flags
var (
	svcLdapURL      string
	svcLdapBindDN   string
	svcLdapBindPass string
	svcLdapBaseDN   string
	svcLdapTLSSkip  bool
	svcPort         int
)

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(serviceUninstallCmd)
	serviceCmd.AddCommand(serviceStartCmd)
	serviceCmd.AddCommand(serviceStopCmd)
	serviceCmd.AddCommand(serviceStatusCmd)
	serviceCmd.AddCommand(serviceRunCmd)

	// Install command flags
	serviceInstallCmd.Flags().StringVar(&svcLdapURL, "ldap-url", "", "LDAP server URL (e.g., ldaps://dc.example.com:636)")
	serviceInstallCmd.Flags().StringVar(&svcLdapBindDN, "ldap-bind-dn", "", "LDAP bind DN")
	serviceInstallCmd.Flags().StringVar(&svcLdapBindPass, "ldap-bind-password", "", "LDAP bind password")
	serviceInstallCmd.Flags().StringVar(&svcLdapBaseDN, "ldap-base-dn", "", "LDAP base DN for searches")
	serviceInstallCmd.Flags().BoolVar(&svcLdapTLSSkip, "ldap-tls-skip-verify", false, "Skip LDAP TLS certificate verification")
	serviceInstallCmd.Flags().IntVar(&svcPort, "port", 8443, "API server port")
}

func runServiceInstall(cmd *cobra.Command, args []string) error {
	// T_106 (follow-up to T_101/server.go): --ldap-bind-password puts the LDAP
	// bind secret in argv, readable by any local user via /proc/<pid>/cmdline for
	// as long as this install command runs. svcLdapBindPass is never read back
	// from viper, so LDAP_BIND_PASSWORD/config.yaml are not an alternative here
	// either — on Linux, installLinuxService below doesn't even consume this
	// value (LDAP is left for the admin GUI or a manual config.yaml edit).
	if cmd.Flags().Changed("ldap-bind-password") {
		log.Warn("--ldap-bind-password was passed on the command line — the secret is readable by any local user for as long as this process runs (e.g. via /proc/<pid>/cmdline on Linux). Omit it and configure LDAP afterwards via the admin GUI or by editing config.yaml directly instead.")
	}

	if runtime.GOOS == "windows" {
		return installWindowsService()
	}
	return installLinuxService()
}

func runServiceUninstall(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return uninstallService()
	}
	return uninstallLinuxService()
}

func runServiceStart(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return startWindowsService()
	}
	return startLinuxService()
}

func runServiceStop(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return stopWindowsService()
	}
	return stopLinuxService()
}

func runServiceStatus(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "windows" {
		return statusWindowsService()
	}
	return statusLinuxService()
}

func runServiceRun(cmd *cobra.Command, args []string) error {
	// This is called by Windows Service Manager
	return runService(false)
}

// linuxLegacyServiceName was this command tree's own systemd unit name/mode
// before B_087 (T_087): "etc-collector" (no "sec"), always `server --port N`,
// WorkingDirectory=/opt/etc-collector (nothing ever creates that directory),
// and NO hardening — a second, divergent product from what `etc-collector
// install` (install.go's linuxServiceFile, "etcsec-collector.service")
// creates, under a customer-facing name that differs by one word. Kept as a
// constant only so uninstallLinuxService can still clean up a unit a prior
// binary version created under the old name; installLinuxService no longer
// writes anything under it.
const linuxLegacyServiceName = "etc-collector"

// Linux service management using systemd.
//
// B_087 (T_087): installLinuxService used to hand-roll the unit shown above
// this comment in git history — a second, unhardened, differently-named
// systemd product from installLinuxSystemdService (install.go), the one
// `etc-collector install` and `etcsec-collector.service`'s `server
// enable`/`disable` (server_toggle.go) already agree on. Established before
// changing anything: install.go and scripts/install.sh already agree with
// each other (same unit name "etcsec-collector.service", same hardening
// block) — this command tree was the sole outlier, on both Linux (this file)
// and Windows (service_windows.go, distinct finding, see delivery). Fixed by
// delegating to the exact same function install.go uses, rather than
// maintaining a second hand-rolled template that can drift again.
//
// mode is hardcoded to "server": this command's own flags/docs
// (serviceInstallCmd's --ldap-* flags, "Manage ETC Collector...standalone")
// only ever implied standalone server mode, matching its historical
// ExecStart of `server --port N`, not `daemon`.
func installLinuxService() error {
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	cfgDir, _, _ := resolvePlatformPaths()

	if err := installLinuxSystemdService(binPath, cfgDir, "server", fmt.Sprintf("--port %d", svcPort)); err != nil {
		return err
	}

	fmt.Println("Service installed successfully")
	fmt.Printf("Configure LDAP via the admin GUI, or edit %s\n", filepath.Join(cfgDir, "config.yaml"))
	fmt.Println("Then run: etc-collector service start")
	return nil
}

func uninstallLinuxService() error {
	exec.Command("systemctl", "stop", "etcsec-collector").Run()
	exec.Command("systemctl", "disable", "etcsec-collector").Run()

	unitPath := filepath.Join(linuxServiceDir, linuxServiceFile)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove unit file: %w", err)
	}

	// Best-effort cleanup of a unit a pre-B_087 binary may have created under
	// the old, divergent name — never written by this binary, but nothing
	// else will ever remove it either.
	exec.Command("systemctl", "stop", linuxLegacyServiceName).Run()
	exec.Command("systemctl", "disable", linuxLegacyServiceName).Run()
	os.Remove(filepath.Join(linuxServiceDir, linuxLegacyServiceName+".service"))

	exec.Command("systemctl", "daemon-reload").Run()

	fmt.Println("Service uninstalled successfully")
	return nil
}

func startLinuxService() error {
	cmd := exec.Command("systemctl", "start", "etcsec-collector")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	fmt.Println("Service started")
	return nil
}

func stopLinuxService() error {
	cmd := exec.Command("systemctl", "stop", "etcsec-collector")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}
	fmt.Println("Service stopped")
	return nil
}

func statusLinuxService() error {
	cmd := exec.Command("systemctl", "status", "etcsec-collector")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run() // Ignore error, status returns non-zero if not running
	return nil
}
