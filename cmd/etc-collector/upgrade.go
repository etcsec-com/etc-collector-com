package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/etcsec-com/etc-collector/internal/upgrade"
)

// Upgrade flags. Mirrors the design in the v3.1.15 plan: a single CLI verb
// that handles every operator-driven binary swap (manifest-driven, manual URL,
// rollback, dry-run, check). Designed to recover hosts that the SaaS-driven
// UPDATE_COLLECTOR cannot — out-of-process is the key property.
var (
	upgradeVersion      string
	upgradeTarget       string
	upgradeCheckOnly    bool
	upgradeRollback     bool
	upgradeNoRestart    bool
	upgradeSkipChecksum bool
	upgradeDownloadURL  string
	upgradeManifestURL  string
	upgradeSHA256       string
	upgradeDryRun       bool
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade the etc-collector binary out-of-process",
	Long: `Replace the installed etc-collector binary with a different version.

Unlike the SaaS-driven UPDATE_COLLECTOR command, ` + "`etc-collector upgrade`" + ` runs
out-of-process: the running daemon doesn't have to swap itself, so this works
even when the deployed binary is broken (the v3.1.12 crash-loop case).

Typical use:

  # Upgrade to the latest published release
  sudo etc-collector upgrade

  # Pin a specific version
  sudo etc-collector upgrade --version 3.1.15

  # Just compare current vs latest, no changes
  etc-collector upgrade --check

  # Restore the previous binary
  sudo etc-collector upgrade --rollback

  # Recover a host stuck on a broken release (run a fresh binary against the
  # broken installed one):
  curl -fsSL https://get.etcsec.com/downloads/3.1.15/etc-collector-3.1.15-linux-amd64.tar.gz | tar xz -C /tmp
  sudo /tmp/etc-collector upgrade --target /var/lib/etc-collector/bin/etc-collector
`,
	// We render our own structured error block — let cobra return non-zero
	// without duplicating the message or printing the usage trailer.
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE:          runUpgrade,
}

func init() {
	rootCmd.AddCommand(upgradeCmd)

	upgradeCmd.Flags().StringVar(&upgradeVersion, "version", "", "Version to install (default: latest from manifest)")
	upgradeCmd.Flags().StringVar(&upgradeTarget, "target", "", "Path of the binary to replace (default: auto-detect)")
	upgradeCmd.Flags().BoolVar(&upgradeCheckOnly, "check", false, "Print current vs target version without making changes")
	upgradeCmd.Flags().BoolVar(&upgradeRollback, "rollback", false, "Restore the previous binary from <target>.bak")
	upgradeCmd.Flags().BoolVar(&upgradeNoRestart, "no-restart", false, "Replace the binary but don't stop/start the service")
	upgradeCmd.Flags().BoolVar(&upgradeSkipChecksum, "skip-checksum", false, "DANGEROUS: skip SHA-256 verification")
	upgradeCmd.Flags().StringVar(&upgradeDownloadURL, "download-url", "", "Direct ZIP URL (skips the manifest); requires --version and --sha256")
	upgradeCmd.Flags().StringVar(&upgradeManifestURL, "manifest-url", "", "Override manifest URL (default: https://get.etcsec.com/downloads/manifest.json)")
	upgradeCmd.Flags().StringVar(&upgradeSHA256, "sha256", "", "Hex-encoded SHA-256 (required with --download-url unless --skip-checksum)")
	upgradeCmd.Flags().BoolVar(&upgradeDryRun, "dry-run", false, "Print what would happen without modifying anything")
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	mgr := upgrade.NewManager()

	plan := upgrade.Plan{
		TargetVersion: upgradeVersion,
		TargetPath:    upgradeTarget,
		DownloadURL:   upgradeDownloadURL,
		SHA256:        upgradeSHA256,
		ManifestURL:   upgradeManifestURL,
		SkipChecksum:  upgradeSkipChecksum,
		NoRestart:     upgradeNoRestart,
		DryRun:        upgradeDryRun,
	}

	// --check: read-only, prints versions, exits 0 if up-to-date else 1.
	if upgradeCheckOnly {
		current, target, err := mgr.CheckOnly(ctx, plan)
		if err != nil {
			printUpgradeError(err)
			return err
		}
		fmt.Printf("Current version : %s\n", emptyDash(current))
		fmt.Printf("Latest version  : %s\n", emptyDash(target))
		if current != "" && current == target {
			fmt.Println("Status          : up-to-date")
			return nil
		}
		fmt.Println("Status          : update available — run 'sudo etc-collector upgrade'")
		os.Exit(1)
		return nil
	}

	// --rollback: bypass everything except backup → target restore.
	if upgradeRollback {
		if err := mgr.Rollback(plan); err != nil {
			printUpgradeError(err)
			return err
		}
		fmt.Println("Rollback complete.")
		return nil
	}

	// Standard upgrade flow.
	plan.CurrentVersion = readSelfVersion(plan.TargetPath)
	mgr.Reporter = &cliReporter{}

	res, err := mgr.Run(ctx, plan)
	if err != nil {
		fmt.Println()
		printUpgradeError(err)
		return err
	}

	fmt.Println()
	if res.Skipped {
		fmt.Printf("Skipped: %s\n", res.Reason)
		return nil
	}
	fmt.Printf("Upgrade complete: %s -> %s\n", emptyDash(res.From), res.To)
	if res.BackupPath != "" {
		fmt.Printf("Backup           : %s\n", res.BackupPath)
	}
	if !plan.NoRestart {
		fmt.Printf("Service active   : %v\n", res.ServiceActive)
	}
	return nil
}

// readSelfVersion runs <target> --version when target is explicit, otherwise
// reports our own compiled-in Version. Used to populate Plan.CurrentVersion
// for the "X -> Y" message and the already-at-version short-circuit.
func readSelfVersion(targetPath string) string {
	if targetPath == "" {
		return Version
	}
	// Best-effort: if the target binary is broken, this returns "" and the
	// upgrade still proceeds (we just lose the "X -> Y" niceness).
	out, err := exec.Command(targetPath, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	return parseFirstSemver(string(out))
}

// printUpgradeError renders an upgrade error in the structured "[CODE] message
// → Fix: …" format the SaaS UI also consumes. Free-form errors fall back to
// their .Error() string.
func printUpgradeError(err error) {
	var ue *upgrade.Error
	if errors.As(err, &ue) {
		fmt.Fprintf(os.Stderr, "\nError: [%s] %s\n", ue.Code, ue.Message)
		if ue.Cause != nil {
			fmt.Fprintf(os.Stderr, "  Cause     : %v\n", ue.Cause)
		}
		if ue.Remediation != "" {
			fmt.Fprintf(os.Stderr, "  Fix       : %s\n", ue.Remediation)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
}

// cliReporter renders the "[N/8]" progress lines the operator expects.
type cliReporter struct{}

func (cliReporter) Step(n, of int, label string) {
	fmt.Printf("[%d/%d] %-32s ", n, of, label)
}
func (cliReporter) OK(detail string)   { fmt.Printf("OK   %s\n", detail) }
func (cliReporter) Fail(detail string) { fmt.Printf("FAIL %s\n", detail) }
func (cliReporter) Note(line string)   { fmt.Printf("...  %s\n", line) }

func emptyDash(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

// parseFirstSemver mirrors the heuristic in upgrade/manager.go for symmetry,
// kept local so the CLI doesn't need to expose internals of the upgrade pkg.
func parseFirstSemver(s string) string {
	for _, tok := range strings.Fields(strings.TrimSpace(s)) {
		parts := strings.Split(tok, ".")
		if len(parts) < 3 {
			continue
		}
		ok := true
		for _, p := range parts[:3] {
			if !isDigits(p) {
				ok = false
				break
			}
		}
		if ok {
			return tok
		}
	}
	return ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
