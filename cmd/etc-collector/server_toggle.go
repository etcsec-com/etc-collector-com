package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/guitoken"
	"github.com/spf13/cobra"
)

var (
	serverEnableHost string
	serverEnablePort int
	serverEnableYes  bool
)

var serverEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable the local admin GUI on this collector",
	Long: `Enable the local admin GUI alongside the SaaS daemon.

This command walks you through the setup interactively, or you can
pass flags to skip the prompts.

INTERACTIVE:
  sudo etc-collector server enable

NON-INTERACTIVE:
  sudo etc-collector server enable --host 0.0.0.0 --port 8443 -y

AFTER ENABLING:
  1. Open the GUI at the URL printed after setup (http:// for local-only,
     https:// for network access — a non-loopback host requires TLS by
     default, see the URL shown)
  2. Enter the GUI access token shown after setup
  3. The SaaS connection continues to work in the background`,
	RunE: runServerEnable,
}

var serverDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable the local admin GUI",
	Long: `Disable the local admin GUI on this collector.

The SaaS daemon continues to run without the local GUI.

EXAMPLE:
  sudo etc-collector server disable`,
	RunE: runServerDisable,
}

func init() {
	serverCmd.AddCommand(serverEnableCmd)
	serverCmd.AddCommand(serverDisableCmd)

	serverEnableCmd.Flags().StringVar(&serverEnableHost, "host", "", "Listen address (127.0.0.1 or 0.0.0.0)")
	serverEnableCmd.Flags().IntVar(&serverEnablePort, "port", 0, "GUI server port")
	serverEnableCmd.Flags().BoolVarP(&serverEnableYes, "yes", "y", false, "Skip confirmation prompts")
}

// askYN prompts the user with a yes/no question and returns the answer.
// defaultYes determines the default when the user just presses Enter.
func askYN(prompt string, defaultYes bool) bool {
	reader := bufio.NewReader(os.Stdin)
	suffix := " [Y/n] "
	if !defaultYes {
		suffix = " [y/N] "
	}
	fmt.Print(prompt + suffix)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer == "" {
		return defaultYes
	}
	return answer == "y" || answer == "yes"
}

// askChoice prompts the user to pick from numbered options.
func askChoice(prompt string, options []string, defaultIdx int) int {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(prompt)
	for i, opt := range options {
		marker := "  "
		if i == defaultIdx {
			marker = "→ "
		}
		fmt.Printf("  %s%d) %s\n", marker, i+1, opt)
	}
	fmt.Printf("  Choice [%d]: ", defaultIdx+1)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(answer)
	if answer == "" {
		return defaultIdx
	}
	n, err := strconv.Atoi(answer)
	if err != nil || n < 1 || n > len(options) {
		return defaultIdx
	}
	return n - 1
}

func runServerEnable(cmd *cobra.Command, args []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("server enable is currently supported on Linux only")
	}

	if os.Getuid() != 0 {
		return fmt.Errorf("this command requires root. Run with sudo")
	}

	cfgDir, _, _ := resolvePlatformPaths()
	unitPath := filepath.Join(linuxServiceDir, linuxServiceFile)

	// Check service file exists
	unitBytes, err := os.ReadFile(unitPath)
	if err != nil {
		return fmt.Errorf("service not installed. Run 'etc-collector install' first")
	}
	unitContent := string(unitBytes)

	// Interactive mode: ask questions if flags not explicitly set
	interactive := !serverEnableYes && isTerminal()

	host := serverEnableHost
	port := serverEnablePort

	if interactive {
		fmt.Println()
		fmt.Println("  ETC Collector — Admin GUI Setup")
		fmt.Println("  ================================")
		fmt.Println()

		// Question 1: Listen mode
		if host == "" {
			choice := askChoice("  Who should access the GUI?", []string{
				"Local only (127.0.0.1) — access via SSH tunnel or locally",
				"Network (0.0.0.0) — accessible from other machines",
			}, 0)
			if choice == 0 {
				host = "127.0.0.1"
			} else {
				host = "0.0.0.0"
			}
			fmt.Println()
		}

		// Question 2: Port
		if port == 0 {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("  Port [8443]: ")
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(answer)
			if answer == "" {
				port = 8443
			} else {
				p, err := strconv.Atoi(answer)
				if err != nil || p < 1 || p > 65535 {
					return fmt.Errorf("invalid port: %s", answer)
				}
				port = p
			}
			fmt.Println()
		}

		// Question 3: Confirm
		if host == "0.0.0.0" {
			fmt.Printf("  The GUI will be accessible from ALL network interfaces on port %d.\n", port)
		} else {
			fmt.Printf("  The GUI will be accessible locally on port %d.\n", port)
		}
		if !askYN("  Proceed?", true) {
			fmt.Println("  Cancelled.")
			return nil
		}
		fmt.Println()
	} else {
		// Non-interactive defaults
		if host == "" {
			host = "127.0.0.1"
		}
		if port == 0 {
			port = 8443
		}
	}

	// Find and update ExecStart line
	lines := strings.Split(unitContent, "\n")
	execIdx := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "ExecStart=") {
			execIdx = i
			break
		}
	}
	if execIdx == -1 {
		return fmt.Errorf("invalid service file: no ExecStart found")
	}

	execLine := strings.TrimSpace(lines[execIdx])
	execLine = removeFlag(execLine, "--gui-host")
	execLine = removeFlag(execLine, "--gui-port")
	execLine = fmt.Sprintf("%s --gui-host %s --gui-port %d", execLine, host, port)
	lines[execIdx] = execLine

	newUnit := strings.Join(lines, "\n")
	if err := os.WriteFile(unitPath, []byte(newUnit), 0644); err != nil {
		return fmt.Errorf("update service file: %w", err)
	}

	// Generate GUI token if not exists
	var newToken string
	if !guitoken.Exists(cfgDir) {
		token, err := guitoken.Generate()
		if err != nil {
			return fmt.Errorf("generate gui token: %w", err)
		}
		hash := guitoken.Hash(token)
		if err := guitoken.SaveHash(cfgDir, hash); err != nil {
			return fmt.Errorf("save gui token hash: %w", err)
		}
		newToken = token
	}

	// Reload and restart
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "restart", "etcsec-collector").Run(); err != nil {
		return fmt.Errorf("restart service: %w", err)
	}

	// Output
	fmt.Println("  Admin GUI enabled!")
	fmt.Println()

	// B_136 (T_060): a non-loopback host now requires TLS by default — the daemon
	// auto-generates a bootstrap self-signed certificate on restart if none is
	// configured (see saas.ResolveGUITLS), so the URL printed here must say https,
	// not the http this used to unconditionally print regardless of host.
	if host == "0.0.0.0" {
		fmt.Printf("  URL:    https://<server-ip>:%d\n", port)
		fmt.Println("  (self-signed certificate — your browser will warn once; this is expected)")
	} else {
		fmt.Printf("  URL:    http://127.0.0.1:%d\n", port)
	}
	fmt.Printf("  Host:   %s\n", host)
	fmt.Printf("  Port:   %d\n", port)

	if newToken != "" {
		fmt.Println()
		fmt.Printf("  Token:  %s\n", newToken)
		fmt.Println()
		fmt.Println("  Save this token — it will not be shown again.")
		fmt.Println("  To reset: etc-collector gui-token reset")
	} else {
		fmt.Println()
		fmt.Println("  Using existing GUI access token.")
		fmt.Println("  Lost it? Run: etc-collector gui-token reset")
	}

	if host == "0.0.0.0" {
		fmt.Println()
		fmt.Printf("  Firewall: make sure port %d is open.\n", port)
	}

	fmt.Println()
	fmt.Println("  Status: sudo systemctl status etcsec-collector")
	fmt.Println("  Logs:   sudo journalctl -u etcsec-collector -f")

	return nil
}

func runServerDisable(cmd *cobra.Command, args []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("server disable is currently supported on Linux only")
	}

	if os.Getuid() != 0 {
		return fmt.Errorf("this command requires root. Run with sudo")
	}

	unitPath := filepath.Join(linuxServiceDir, linuxServiceFile)

	unitBytes, err := os.ReadFile(unitPath)
	if err != nil {
		return fmt.Errorf("service not installed")
	}
	unitContent := string(unitBytes)

	lines := strings.Split(unitContent, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ExecStart=") {
			cleaned := removeFlag(trimmed, "--gui-host")
			cleaned = removeFlag(cleaned, "--gui-port")
			cleaned = cleaned + " --gui-port 0"
			lines[i] = cleaned
			break
		}
	}

	newUnit := strings.Join(lines, "\n")
	if err := os.WriteFile(unitPath, []byte(newUnit), 0644); err != nil {
		return fmt.Errorf("update service file: %w", err)
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "restart", "etcsec-collector").Run(); err != nil {
		return fmt.Errorf("restart service: %w", err)
	}

	fmt.Println("Admin GUI disabled.")
	fmt.Println("The SaaS daemon continues to run.")
	return nil
}

// removeFlag removes a flag and its value from a command line string
func removeFlag(cmdLine, flag string) string {
	parts := strings.Fields(cmdLine)
	var result []string
	skip := false
	for _, part := range parts {
		if skip {
			skip = false
			continue
		}
		if part == flag {
			skip = true
			continue
		}
		if strings.HasPrefix(part, flag+"=") {
			continue
		}
		result = append(result, part)
	}
	return strings.Join(result, " ")
}

// isTerminal returns true if stdin is a terminal (not piped)
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
