package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/guitoken"
	"github.com/etcsec-com/etc-collector/internal/saas"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Installation paths per platform.
//
// Layout v3.0.23+ on Unix: the real binary lives under DATA_DIR/bin (writable
// area covered by ReadWritePaths) and a symlink in /usr/local/bin keeps it on
// $PATH. This lets the daemon swap the binary in-place via syscall.Exec without
// relaxing the systemd hardening.
const (
	// Linux
	linuxConfigDir   = "/etc/etc-collector"
	linuxDataDir     = "/var/lib/etc-collector"
	linuxBinDir      = "/var/lib/etc-collector/bin" // real binary location (writable)
	linuxBinSymlink  = "/usr/local/bin/etc-collector"
	linuxServiceDir  = "/etc/systemd/system"
	linuxServiceFile = "etcsec-collector.service"

	// Darwin
	darwinConfigDir  = "/etc/etc-collector"
	darwinDataDir    = "/var/lib/etc-collector"
	darwinBinDir     = "/var/lib/etc-collector/bin" // real binary location
	darwinBinSymlink = "/usr/local/bin/etc-collector"
	darwinPlistDir   = "/Library/LaunchDaemons"
	darwinPlistFile  = "com.etcsec.collector.plist"

	// Windows (no symlink dance — Windows can't rename a running .exe in-process)
	windowsBinDir  = `C:\Program Files\ETCSec`
	windowsDataDir = `C:\ProgramData\ETCSec\etc-collector`
)

// installUpgrade is the --upgrade flag. When true, runInstall acts as a
// migration: detect the legacy /usr/local/bin layout, move the binary to the
// new internal location, recreate the symlink, and rewrite the systemd unit
// to point to the new ExecStart path.
var installUpgrade bool

var (
	installEnrollToken      string
	installEnrollTokenFile  string
	installEnrollTokenStdin bool
	installSaaSURL          string
	installConfigDirFlag    string
	installDataDirFlag      string
	installMode             string

	uninstallPurge bool
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install ETC Collector as a system service",
	Long: `Install ETC Collector as a system service.

Copies the binary to the system path, creates required directories,
installs the service (systemd/launchd/Windows SCM), and optionally
enrolls with the SaaS platform.

Examples:
  # SaaS mode: install + enroll in one command
  sudo ETCSEC_ENROLL_TOKEN=xxx ./etc-collector install --saas-url https://api.etcsec.com

  # Standalone server mode
  sudo ./etc-collector install --mode server

  # Just install, enroll later
  sudo ./etc-collector install`,
	RunE: runInstall,
}

var uninstallTopCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall ETC Collector system service",
	Long: `Uninstall ETC Collector from the system.

Stops the service, notifies the SaaS backend (best-effort),
removes the service and binary. Use --purge to also remove
configuration and data directories.`,
	RunE: runUninstall,
}

func init() {
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallTopCmd)

	// Install flags
	installCmd.Flags().StringVar(&installEnrollToken, "enroll-token", "", "SaaS enrollment token (or ETCSEC_ENROLL_TOKEN env). Visible in argv/process listings and shell history — prefer --enroll-token-file or --enroll-token-stdin.")
	installCmd.Flags().StringVar(&installEnrollTokenFile, "enroll-token-file", "", "Read the enrollment token from this file, once at startup — never placed in argv or the environment")
	installCmd.Flags().BoolVar(&installEnrollTokenStdin, "enroll-token-stdin", false, "Read the enrollment token as a single line from stdin (explicit — not autodetected from a pipe)")
	installCmd.Flags().StringVar(&installSaaSURL, "saas-url", "", "SaaS API URL (required with --enroll-token, https)")
	installCmd.Flags().BoolVar(&allowInsecureSaaSURL, "allow-insecure-saas-url", false,
		"Allow a plaintext http:// SaaS URL (local test backends only — the enrollment token travels in the clear)")
	installCmd.Flags().StringVar(&installMode, "mode", "", "Service mode: 'saas' (default) or 'server'")
	installCmd.Flags().StringVar(&installConfigDirFlag, "config-dir", "", "Override config directory")
	installCmd.Flags().StringVar(&installDataDirFlag, "data-dir", "", "Override data directory")
	installCmd.Flags().BoolVar(&installUpgrade, "upgrade", false, "Migrate an existing install to the v3.0.23+ layout (binary in DATA_DIR/bin + symlink in /usr/local/bin) and rewrite the systemd unit accordingly. Idempotent.")

	// Uninstall flags
	uninstallTopCmd.Flags().BoolVar(&uninstallPurge, "purge", false, "Remove all data and configuration")
}

// resolveEnrollToken applies B_030/T_045's precedence for how the enrollment token
// reaches the process: --enroll-token (explicit flag, existing) > --enroll-token-file /
// --enroll-token-stdin (new — read once at startup, never placed in argv or the
// environment, what TL Cloud's installer expects) > ETCSEC_ENROLL_TOKEN env > viper
// (config file). --enroll-token-file and --enroll-token-stdin are mutually exclusive —
// providing both is a usage error, not a silent pick between them.
//
// stdin is a parameter (not a bare os.Stdin read) so tests can supply a fake reader.
// --enroll-token-stdin must be explicit: a binary that reads stdin "when it looks like
// a pipe" behaves unpredictably in CI and in scripts.
func resolveEnrollToken(flagToken, tokenFile string, tokenStdin bool, stdin io.Reader, viperToken string) (string, error) {
	if flagToken != "" {
		return flagToken, nil
	}

	if tokenFile != "" && tokenStdin {
		return "", fmt.Errorf("--enroll-token-file and --enroll-token-stdin are mutually exclusive")
	}

	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read --enroll-token-file %s: %w", tokenFile, err)
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("--enroll-token-file %s is empty", tokenFile)
		}
		return token, nil
	}

	if tokenStdin {
		scanner := bufio.NewScanner(stdin)
		var token string
		if scanner.Scan() {
			token = strings.TrimSpace(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("read --enroll-token-stdin: %w", err)
		}
		if token == "" {
			return "", fmt.Errorf("--enroll-token-stdin: no token read from stdin")
		}
		return token, nil
	}

	if v := os.Getenv("ETCSEC_ENROLL_TOKEN"); v != "" {
		return v, nil
	}

	return viperToken, nil
}

func runInstall(cmd *cobra.Command, args []string) error {
	// --upgrade: idempotent migration to the v3.0.23+ layout.
	// Detect the legacy /usr/local/bin install, move binary, recreate symlink,
	// rewrite the systemd unit, restart the service. Then return.
	if installUpgrade {
		return runInstallUpgrade()
	}

	// Resolve enrollment token — B_030/T_045 precedence: explicit flag >
	// file/stdin > env > viper config file. See resolveEnrollToken.
	enrollToken, err := resolveEnrollToken(installEnrollToken, installEnrollTokenFile, installEnrollTokenStdin, os.Stdin, viper.GetString("enroll.token"))
	if err != nil {
		return err
	}

	// Resolve SaaS URL
	saasInstallURL := installSaaSURL
	if saasInstallURL == "" {
		saasInstallURL = viper.GetString("saas.url")
	}
	if saasInstallURL == "" {
		saasInstallURL = os.Getenv("ETCSEC_SAAS_URL")
	}

	// Determine mode
	mode := installMode
	if mode == "" {
		if enrollToken != "" {
			mode = "saas"
		} else {
			mode = "server"
		}
	}

	// Validate: SaaS mode with token requires URL
	if enrollToken != "" && saasInstallURL == "" {
		return fmt.Errorf("--saas-url required when enrollment token is provided")
	}
	// A_004 K8 — same cleartext refusal as `enroll`; the installer is the path
	// customers actually use, so it must not be the one that skips the check.
	if enrollToken != "" {
		if err := saas.ValidateSaaSURL(saasInstallURL, allowInsecureSaaSURL); err != nil {
			return err
		}
		if saas.IsPlaintextSaaSURL(saasInstallURL) {
			fmt.Printf("  [WARN] Enrolling over PLAINTEXT HTTP (%s) — token and commands travel in the clear\n", saasInstallURL)
		}
	}

	// Resolve paths
	cfgDir, dataDir, binDir := resolvePlatformPaths()
	if installConfigDirFlag != "" {
		cfgDir = installConfigDirFlag
	}
	if installDataDirFlag != "" {
		dataDir = installDataDirFlag
	}

	fmt.Printf("Installing ETC Collector (%s mode)...\n", mode)
	fmt.Printf("  Binary:  %s\n", filepath.Join(binDir, binaryName()))
	fmt.Printf("  Config:  %s\n", cfgDir)
	fmt.Printf("  Data:    %s\n", dataDir)

	// Step 1: Copy binary to system path
	if err := copyBinaryToSystem(binDir); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	fmt.Println("  [OK] Binary installed")

	// Step 2: Create directories
	if err := createDirectories(cfgDir, dataDir); err != nil {
		return fmt.Errorf("create directories: %w", err)
	}
	fmt.Println("  [OK] Directories created")

	// Step 3: Generate GUI access token (only on fresh install)
	var guiToken string
	if !guitoken.Exists(cfgDir) {
		var err error
		guiToken, err = guitoken.Generate()
		if err != nil {
			return fmt.Errorf("generate gui token: %w", err)
		}
		hash := guitoken.Hash(guiToken)
		if err := guitoken.SaveHash(cfgDir, hash); err != nil {
			return fmt.Errorf("save gui token hash: %w", err)
		}
		fmt.Println("  [OK] GUI access token generated")
	}

	// Step 4: Enroll (if token provided)
	if enrollToken != "" {
		daemon, err := saas.NewDaemon(cfgDir, Version, Edition)
		if err != nil {
			return fmt.Errorf("create daemon: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		fmt.Printf("  Enrolling with %s...\n", saasInstallURL)
		if err := daemon.Enroll(ctx, enrollToken, saasInstallURL); err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}

		creds, _ := daemon.LoadCredentials()
		if creds != nil {
			fmt.Printf("  [OK] Enrolled as %s\n", creds.CollectorID)
		}
	}

	// Step 5: Install service
	binPath := filepath.Join(binDir, binaryName())
	if err := installService(binPath, cfgDir, mode); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	fmt.Println("  [OK] Service installed")

	// Step 6: Start service (only if enrollment succeeded or server mode)
	if enrollToken != "" || mode == "server" {
		if err := startInstalledService(); err != nil {
			fmt.Printf("  [WARN] Service not started: %v\n", err)
			fmt.Println("  Start manually after configuration.")
		} else {
			fmt.Println("  [OK] Service started")
		}
	}

	fmt.Printf("\nETC Collector %s (%s) installed successfully!\n", Version, Edition)
	fmt.Println("By using this software, you agree to the Functional Source License (FSL-1.1-ALv2).")
	fmt.Println("Run 'etc-collector license' to view the full license terms.")

	if guiToken != "" {
		fmt.Println()
		fmt.Printf("  GUI:    http://localhost:8443\n")
		fmt.Printf("  Token:  %s\n", guiToken)
		fmt.Println()
		fmt.Println("  Save this token — it will not be shown again.")
		fmt.Println("  To reset: etc-collector gui-token reset")
	}

	// Interactive: ask to enable the admin GUI after SaaS install
	if mode == "saas" && enrollToken != "" && isTerminal() && runtime.GOOS == "linux" {
		fmt.Println()
		if askYN("Enable the local admin GUI?", true) {
			fmt.Println()
			// Run server enable logic inline
			serverEnableYes = true // skip re-confirmation
			serverEnableHost = "127.0.0.1"
			serverEnablePort = 8443

			choice := askChoice("  Who should access the GUI?", []string{
				"Local only (127.0.0.1) — access via SSH tunnel or locally",
				"Network (0.0.0.0) — accessible from other machines",
			}, 0)
			if choice == 1 {
				serverEnableHost = "0.0.0.0"
			}

			fmt.Println()
			if err := runServerEnable(cmd, nil); err != nil {
				fmt.Printf("  [WARN] GUI setup failed: %v\n", err)
				fmt.Println("  You can enable it later: sudo etc-collector server enable")
			}
		} else {
			fmt.Println()
			fmt.Println("  To enable later: sudo etc-collector server enable")
		}
	}

	if enrollToken == "" && mode == "saas" {
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Enroll: etc-collector enroll TOKEN --saas-url URL")
		fmt.Println("  2. Start:  sudo systemctl start etcsec-collector")
	}
	return nil
}

func runUninstall(cmd *cobra.Command, args []string) error {
	cfgDir, dataDir, binDir := resolvePlatformPaths()

	fmt.Println("Uninstalling ETC Collector...")

	// Step 1: Best-effort unenroll from SaaS
	credStore := saas.NewCredentialStore(cfgDir)
	if credStore.Exists() {
		daemon, err := saas.NewDaemon(cfgDir, Version, Edition)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := daemon.UnenrollRemote(ctx); err != nil {
				fmt.Printf("  [WARN] SaaS notification failed: %v\n", err)
			} else {
				fmt.Println("  [OK] SaaS backend notified")
			}
			cancel()
		}
	}

	// Step 2: Stop and remove service
	if err := stopInstalledService(); err != nil {
		fmt.Printf("  [WARN] Service stop: %v\n", err)
	}
	if err := removeInstalledService(); err != nil {
		fmt.Printf("  [WARN] Service removal: %v\n", err)
	} else {
		fmt.Println("  [OK] Service removed")
	}

	// Step 3: Remove binary + /usr/local/bin symlink (Unix)
	binPath := filepath.Join(binDir, binaryName())
	if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("  [WARN] Remove binary: %v\n", err)
	} else {
		fmt.Println("  [OK] Binary removed")
	}
	if symPath := platformSymlinkPath(); symPath != "" {
		if err := os.Remove(symPath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("  [WARN] Remove symlink %s: %v\n", symPath, err)
		}
	}
	// Cleanup .bak files left by previous in-place upgrades
	for _, p := range []string{binPath + ".bak"} {
		os.Remove(p)
	}

	// Step 4: Purge data if requested
	if uninstallPurge {
		if err := os.RemoveAll(cfgDir); err != nil {
			fmt.Printf("  [WARN] Remove config: %v\n", err)
		}
		if err := os.RemoveAll(dataDir); err != nil {
			fmt.Printf("  [WARN] Remove data: %v\n", err)
		}
		fmt.Println("  [OK] Data and config purged")
	}

	fmt.Println("\nUninstall complete.")
	if !uninstallPurge {
		fmt.Printf("Config and data preserved in %s and %s\n", cfgDir, dataDir)
		fmt.Println("Use --purge to remove everything.")
	}
	return nil
}

// resolvePlatformPaths returns config, data, and bin directories for the current platform
func resolvePlatformPaths() (configDir, dataDir, binDir string) {
	switch runtime.GOOS {
	case "darwin":
		return darwinConfigDir, darwinDataDir, darwinBinDir
	case "windows":
		return windowsDataDir, windowsDataDir, windowsBinDir
	default: // linux
		return linuxConfigDir, linuxDataDir, linuxBinDir
	}
}

// binaryName returns the binary filename for the current platform
func binaryName() string {
	if runtime.GOOS == "windows" {
		return "etc-collector.exe"
	}
	return "etc-collector"
}

// copyBinaryToSystem copies the current executable to the system bin directory.
// On Unix, also creates the /usr/local/bin symlink so the new binary is on $PATH.
func copyBinaryToSystem(binDir string) error {
	srcPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	// Resolve symlinks
	srcPath, err = filepath.EvalSymlinks(srcPath)
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	dstPath := filepath.Join(binDir, binaryName())

	// Ensure bin directory exists
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("create bin directory: %w", err)
	}

	// Copy if source != destination (skip self-overwrite)
	if srcPath != dstPath {
		if err := atomicCopyFile(srcPath, dstPath); err != nil {
			return err
		}
	}

	// Create the /usr/local/bin symlink (Unix only).
	if symPath := platformSymlinkPath(); symPath != "" {
		if err := ensureSymlink(dstPath, symPath); err != nil {
			return fmt.Errorf("create symlink %s -> %s: %w", symPath, dstPath, err)
		}
	}
	return nil
}

// atomicCopyFile copies src to a temp file beside dst then renames into place.
// Uses 0755 mode so the resulting binary is executable.
func atomicCopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer in.Close()

	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("create temp dest: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp dest: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename temp into place: %w", err)
	}
	return nil
}

// platformSymlinkPath returns the /usr/local/bin symlink for Unix platforms,
// or "" on Windows (no symlink dance).
func platformSymlinkPath() string {
	switch runtime.GOOS {
	case "linux":
		return linuxBinSymlink
	case "darwin":
		return darwinBinSymlink
	default:
		return ""
	}
}

// ensureSymlink makes dst a symlink pointing to src. Idempotent: if dst is
// already a symlink to src, no-op. If dst is a regular file or wrong link,
// it is removed and recreated.
func ensureSymlink(src, dst string) error {
	info, err := os.Lstat(dst)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			if current, lerr := os.Readlink(dst); lerr == nil && current == src {
				return nil // already correct
			}
		}
		if err := os.Remove(dst); err != nil {
			return fmt.Errorf("remove existing %s: %w", dst, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", dst, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("mkdir parent of %s: %w", dst, err)
	}
	return os.Symlink(src, dst)
}

// createDirectories creates config and data directories with appropriate permissions.
//
// A_004 K7(b): the config directory used to be 0755 while the data directory next to it
// was already 0700. saas.SecureDir applies 0700 to both AND chmods a directory that
// already exists — without that, every collector already in the field would keep its
// 0755 config directory forever, since MkdirAll's mode is ignored for existing paths.
func createDirectories(cfgDir, dataDir string) error {
	if err := saas.SecureDir(cfgDir); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := saas.SecureDir(dataDir); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return nil
}

// installService installs the system service (platform-specific)
func installService(binPath, cfgDir, mode string) error {
	switch runtime.GOOS {
	case "linux":
		return installLinuxSystemdService(binPath, cfgDir, mode, "")
	case "darwin":
		return installDarwinLaunchdService(binPath, cfgDir, mode)
	case "windows":
		return installWindowsSCMService(binPath, mode)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// startInstalledService starts the installed service
func startInstalledService() error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("systemctl", "start", "etcsec-collector").Run()
	case "darwin":
		return exec.Command("launchctl", "load", filepath.Join(darwinPlistDir, darwinPlistFile)).Run()
	case "windows":
		return startWindowsSCMService()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// stopInstalledService stops the installed service
func stopInstalledService() error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("systemctl", "stop", "etcsec-collector").Run()
	case "darwin":
		return exec.Command("launchctl", "unload", filepath.Join(darwinPlistDir, darwinPlistFile)).Run()
	case "windows":
		return stopWindowsSCMService()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// removeInstalledService removes the installed service
func removeInstalledService() error {
	switch runtime.GOOS {
	case "linux":
		exec.Command("systemctl", "disable", "etcsec-collector").Run()
		unitPath := filepath.Join(linuxServiceDir, linuxServiceFile)
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		exec.Command("systemctl", "daemon-reload").Run()
		return nil
	case "darwin":
		plistPath := filepath.Join(darwinPlistDir, darwinPlistFile)
		if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	case "windows":
		return removeWindowsSCMService()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// installLinuxSystemdService creates and enables a systemd unit.
//
// binPath must be the *real* binary path (under DATA_DIR/bin), not the
// /usr/local/bin symlink. This ensures os.Executable() inside the daemon
// returns the writable path and lets syscall.Exec do an in-place upgrade.
// extraArgs is appended verbatim to ExecStart's argument list — B_087
// (T_087): service.go's `service install --port N` used to be the only place
// a custom API port could be set at install time; preserved here rather than
// silently dropped when service.go started delegating to this function.
// buildLinuxSystemdUnit renders the unit file content — split out from
// installLinuxSystemdService (B_087, T_087) so the exact text every install
// path produces can be asserted in a test without touching the filesystem or
// systemctl.
func buildLinuxSystemdUnit(binPath, cfgDir, mode, extraArgs string) string {
	execStart := fmt.Sprintf("%s daemon --config-dir %s", binPath, cfgDir)
	if mode == "server" {
		execStart = fmt.Sprintf("%s server", binPath)
	}
	if extraArgs != "" {
		execStart = execStart + " " + extraArgs
	}

	return fmt.Sprintf(`[Unit]
Description=ETC Collector - Identity Security Audit
Documentation=https://github.com/etcsec-com/etc-collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=10
User=root
WorkingDirectory=%s

# Hardening — binary lives under ReadWritePaths so in-place upgrade works
# without relaxing ProtectSystem (see docs/configuration/update-mechanism.md).
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=%s %s
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`, execStart, linuxDataDir, cfgDir, linuxDataDir)
}

func installLinuxSystemdService(binPath, cfgDir, mode, extraArgs string) error {
	unit := buildLinuxSystemdUnit(binPath, cfgDir, mode, extraArgs)

	unitPath := filepath.Join(linuxServiceDir, linuxServiceFile)
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}

	if err := exec.Command("systemctl", "enable", "etcsec-collector").Run(); err != nil {
		return fmt.Errorf("systemctl enable: %w", err)
	}

	return nil
}

// installDarwinLaunchdService creates a launchd plist
func installDarwinLaunchdService(binPath, cfgDir, mode string) error {
	programArgs := fmt.Sprintf(`    <string>%s</string>
    <string>daemon</string>
    <string>--config-dir</string>
    <string>%s</string>`, binPath, cfgDir)

	if mode == "server" {
		programArgs = fmt.Sprintf(`    <string>%s</string>
    <string>server</string>`, binPath)
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.etcsec.collector</string>
  <key>ProgramArguments</key>
  <array>
%s
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>%s</string>
  <key>StandardOutPath</key>
  <string>/var/log/etc-collector.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/etc-collector.err</string>
</dict>
</plist>
`, programArgs, darwinDataDir)

	plistPath := filepath.Join(darwinPlistDir, darwinPlistFile)
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write launchd plist: %w", err)
	}

	return nil
}
