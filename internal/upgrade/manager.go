package upgrade

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Disk space margins. Sized to fit the worst-case (Windows binary ~50 MB)
// times the three copies we need at peak: target + .bak + new.
const (
	minDestFreeBytes = 200 * 1024 * 1024 // 200 MB on the binary's filesystem
	minTmpFreeBytes  = 100 * 1024 * 1024 // 100 MB on the staging filesystem
)

// Service control timeouts. Generous defaults — the systemd unit's own start
// can take ~10s on enrolled hosts (LDAP TLS + SaaS handshake), Windows SCM is
// even slower. Caller can shorten via Plan if needed.
const (
	defaultStopTimeout  = 30 * time.Second
	defaultStartTimeout = 30 * time.Second
)

// Plan captures everything the user/CLI decided up front. It's filled by
// the CLI command from flags, then handed to Run which executes it.
type Plan struct {
	// TargetVersion is the version we're upgrading to (e.g. "3.1.15"). When
	// empty or "latest", Run resolves it via the manifest.
	TargetVersion string

	// TargetPath is the on-disk binary that gets replaced. Empty = auto-detect
	// from the running executable (os.Executable + EvalSymlinks).
	TargetPath string

	// DownloadURL overrides the manifest. When set, SHA256 must also be set
	// (or SkipChecksum=true). This is the unattended/air-gapped escape hatch.
	DownloadURL string
	SHA256      string // hex, no "sha256:" prefix; required unless SkipChecksum

	// ManifestURL overrides DefaultManifestURL.
	ManifestURL string

	// SkipChecksum disables SHA-256 verification — DANGEROUS, only for
	// dev / air-gapped scenarios. Logged in red on the CLI.
	SkipChecksum bool

	// NoRestart skips the service stop/start phase. Useful when the operator
	// wants to control the cutover manually.
	NoRestart bool

	// DryRun prints what would happen without modifying anything.
	DryRun bool

	// CurrentVersion is the version of the running TargetPath, captured by
	// the CLI before invoking Run (so the result message can say "3.1.13 → …").
	// Optional — Run still works without it.
	CurrentVersion string
}

// Result describes what Run did, for the CLI to print as a summary.
type Result struct {
	From          string
	To            string
	BackupPath    string
	ServiceActive bool
	Skipped       bool   // true when already-at-version short-circuit fired
	Reason        string // free-form, when Skipped
}

// Reporter is the optional progress callback. The CLI implements this to
// render "[3/8] Downloading …" lines. nil = silent.
type Reporter interface {
	Step(n int, of int, label string)
	OK(detail string)
	Fail(detail string)
	Note(line string)
}

// Manager orchestrates one upgrade. It's stateless — re-usable across runs.
type Manager struct {
	HTTP     *http.Client
	Service  ServiceController
	Reporter Reporter
}

// NewManager returns a Manager wired with sensible defaults: a 10 min HTTP
// client (matches the SaaS update pattern in internal/saas/update.go) and the
// platform service controller.
func NewManager() *Manager {
	return &Manager{
		HTTP:     &http.Client{Timeout: 10 * time.Minute},
		Service:  NewServiceController(),
		Reporter: nopReporter{},
	}
}

// Run executes the upgrade plan. Returns either a populated Result on success
// or an *Error with a stable Code on failure. Run is best-effort idempotent:
// already-at-version → Skipped=true, no error.
func (m *Manager) Run(ctx context.Context, plan Plan) (*Result, error) {
	rep := m.Reporter
	if rep == nil {
		rep = nopReporter{}
	}

	// ── Step 1/8 — pre-flight ─────────────────────────────────────────
	rep.Step(1, 8, "Pre-flight checks")

	target, err := m.resolveTarget(plan.TargetPath)
	if err != nil {
		rep.Fail(err.Error())
		return nil, err
	}
	plan.TargetPath = target

	if err := preflightDisk(target); err != nil {
		rep.Fail(err.Error())
		return nil, err
	}
	if err := preflightWritable(target); err != nil {
		rep.Fail(err.Error())
		return nil, err
	}
	rep.OK(fmt.Sprintf("target=%s", target))

	// ── Step 2/8 — resolve version ────────────────────────────────────
	rep.Step(2, 8, "Resolving target version")

	version, dlURL, sha, err := m.resolveSource(ctx, plan)
	if err != nil {
		rep.Fail(err.Error())
		return nil, err
	}
	plan.TargetVersion = version

	// Already-at-version short-circuit. Captures the common idempotent case
	// where an operator runs `etc-collector upgrade` on a host already
	// matching the latest.
	if plan.CurrentVersion != "" && plan.CurrentVersion == version {
		rep.OK(fmt.Sprintf("already at %s — nothing to do", version))
		return &Result{From: version, To: version, Skipped: true, Reason: "already-at-version"}, nil
	}
	rep.OK(fmt.Sprintf("version=%s", version))

	// Dry-run stops here. The remaining steps would mutate filesystem/service.
	if plan.DryRun {
		rep.Note(fmt.Sprintf("DRY RUN — would download %s and replace %s", dlURL, target))
		return &Result{From: plan.CurrentVersion, To: version, Skipped: true, Reason: "dry-run"}, nil
	}

	// ── Step 3/8 — download ───────────────────────────────────────────
	rep.Step(3, 8, "Downloading")
	stagingDir, err := m.stagingDir(target)
	if err != nil {
		rep.Fail(err.Error())
		return nil, err
	}
	defer os.RemoveAll(stagingDir)

	archive := filepath.Join(stagingDir, "update.zip")
	if err := m.download(ctx, dlURL, archive); err != nil {
		rep.Fail(err.Error())
		return nil, err
	}
	rep.OK("downloaded")

	// ── Step 4/8 — verify ─────────────────────────────────────────────
	rep.Step(4, 8, "Verifying SHA-256")
	if plan.SkipChecksum {
		rep.Note("SHA-256 verification SKIPPED (--skip-checksum)")
	} else {
		if err := verifyChecksum(archive, sha); err != nil {
			rep.Fail(err.Error())
			return nil, err
		}
		rep.OK("match")
	}

	// ── Step 5/8 — extract + sanity check ────────────────────────────
	rep.Step(5, 8, "Extracting + sanity check")
	extracted := filepath.Join(stagingDir, binaryName())
	if err := extractBinaryFromZip(archive, extracted); err != nil {
		rep.Fail(err.Error())
		return nil, err
	}
	if err := sanityCheckBinary(extracted, version); err != nil {
		rep.Fail(err.Error())
		return nil, err
	}
	rep.OK("binary OK")

	// ── Step 6/8 — stop service ──────────────────────────────────────
	rep.Step(6, 8, "Stopping service")
	if plan.NoRestart || !m.Service.IsInstalled() {
		rep.Note("skipped (no-restart or no service)")
	} else {
		if err := m.Service.Stop(defaultStopTimeout); err != nil {
			rep.Fail(err.Error())
			return nil, newErr(CodeServiceStopFailed,
				fmt.Sprintf("failed to stop %s", m.Service.Name()),
				"Stop the service manually then re-run --no-restart.", err)
		}
		rep.OK("stopped")
	}

	// ── Step 7/8 — backup + atomic replace ───────────────────────────
	rep.Step(7, 8, "Backup + atomic replace")
	backup := target + ".bak"
	if err := backupFile(target, backup); err != nil {
		rep.Fail(err.Error())
		// If backup failed, try to restart whatever was running.
		_ = m.Service.Start(defaultStartTimeout)
		return nil, err
	}
	if err := installFile(extracted, target); err != nil {
		rep.Fail(err.Error())
		// Best-effort rollback before we lose the chance.
		if rollErr := os.Rename(backup, target); rollErr == nil {
			_ = m.Service.Start(defaultStartTimeout)
		}
		return nil, err
	}
	rep.OK("backup at " + backup)

	// ── Step 8/8 — start + health-check ──────────────────────────────
	rep.Step(8, 8, "Starting service")
	if plan.NoRestart || !m.Service.IsInstalled() {
		rep.Note("skipped (no-restart or no service)")
		return &Result{
			From: plan.CurrentVersion, To: version,
			BackupPath: backup, ServiceActive: false,
		}, nil
	}
	if err := m.Service.Start(defaultStartTimeout); err != nil {
		rep.Fail("start failed → rolling back")
		// Auto-rollback: restore backup and try to start again.
		if rbErr := os.Rename(backup, target); rbErr != nil {
			return nil, newErr(CodeRollbackFailed,
				"failed to restore backup after failed start",
				"Manually restore: cp "+backup+" "+target+" && systemctl start "+m.Service.Name(),
				rbErr)
		}
		_ = m.Service.Start(defaultStartTimeout)
		return nil, newErr(CodeHealthCheckFailed,
			fmt.Sprintf("service did not start on %s — rolled back to previous version", version),
			"Investigate the underlying failure (logs) before re-attempting.", err)
	}
	active, _ := m.Service.IsActive()
	rep.OK(fmt.Sprintf("active=%v version=%s", active, version))

	return &Result{
		From: plan.CurrentVersion, To: version,
		BackupPath: backup, ServiceActive: active,
	}, nil
}

// CheckOnly compares current version with the manifest's target. No changes.
func (m *Manager) CheckOnly(ctx context.Context, plan Plan) (current, target string, err error) {
	exe, rerr := m.resolveTarget(plan.TargetPath)
	if rerr != nil {
		return "", "", rerr
	}
	current = readBinaryVersion(exe)
	if plan.DownloadURL != "" {
		// User overrode the URL, so no manifest fetch — just print "current".
		return current, plan.TargetVersion, nil
	}
	manifest, ferr := FetchManifest(ctx, plan.ManifestURL)
	if ferr != nil {
		return current, "", ferr
	}
	v, _, verr := manifest.ResolveVersion(plan.TargetVersion)
	if verr != nil {
		return current, v, verr
	}
	return current, v, nil
}

// Rollback restores <target>.bak → <target> and (optionally) restarts.
// Returns CodeRollbackUnavailable when no .bak exists.
func (m *Manager) Rollback(plan Plan) error {
	target, err := m.resolveTarget(plan.TargetPath)
	if err != nil {
		return err
	}
	backup := target + ".bak"
	if _, err := os.Stat(backup); err != nil {
		return newErr(CodeRollbackUnavailable,
			"no backup found at "+backup,
			"Reinstall manually with --version <X>.", err)
	}
	if !plan.NoRestart && m.Service.IsInstalled() {
		_ = m.Service.Stop(defaultStopTimeout)
	}
	if err := os.Rename(backup, target); err != nil {
		return newErr(CodeRollbackFailed, "rename failed", "Restore "+backup+" manually.", err)
	}
	if !plan.NoRestart && m.Service.IsInstalled() {
		if err := m.Service.Start(defaultStartTimeout); err != nil {
			return newErr(CodeServiceStartFailed,
				"service did not start after rollback",
				"Investigate logs.", err)
		}
	}
	return nil
}

// ─── helpers ────────────────────────────────────────────────────────────

// resolveTarget picks the binary to replace. Auto-detect = the path of the
// currently-running executable, with symlinks resolved (so we operate on the
// real file under /var/lib/etc-collector/bin, not the /usr/local/bin alias).
func (m *Manager) resolveTarget(explicit string) (string, error) {
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return "", newErr(CodeTargetNotFound, "invalid --target path", "", err)
		}
		if _, err := os.Stat(abs); err != nil {
			return "", newErr(CodeTargetNotFound, "target binary not found at "+abs,
				"Pass --target with a path that exists.", err)
		}
		return abs, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", newErr(CodeTargetNotFound, "cannot locate running binary",
			"Pass --target /var/lib/etc-collector/bin/etc-collector explicitly.", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}

// resolveSource decides where to download from. Explicit URL wins. Otherwise
// fetch the manifest, pick the version + artifact, return URL + sha.
func (m *Manager) resolveSource(ctx context.Context, plan Plan) (version, url, sha string, err error) {
	if plan.DownloadURL != "" {
		if plan.TargetVersion == "" {
			return "", "", "", newErr(CodeVersionNotFound,
				"--download-url requires --version <X.Y.Z>",
				"Pass --version explicitly so the binary can self-identify.", nil)
		}
		if !plan.SkipChecksum && plan.SHA256 == "" {
			return "", "", "", newErr(CodeChecksumMismatch,
				"--download-url requires --sha256 (or --skip-checksum, dangerous)",
				"Provide the published SHA-256 for the binary.", nil)
		}
		return plan.TargetVersion, plan.DownloadURL, plan.SHA256, nil
	}

	manifest, err := FetchManifest(ctx, plan.ManifestURL)
	if err != nil {
		return "", "", "", err
	}
	v, art, err := manifest.ResolveVersion(plan.TargetVersion)
	if err != nil {
		return v, "", "", err
	}
	return v, art.URL, art.SHA256, nil
}

func (m *Manager) stagingDir(target string) (string, error) {
	// Stage on the same filesystem as the target so the final rename is atomic
	// (cross-FS rename returns EXDEV — same trap the SaaS daemon hit pre-3.1.13).
	dir := filepath.Join(filepath.Dir(target), ".upgrade-staging")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", newErr(CodeInternal, "create staging dir", "Check permissions on "+filepath.Dir(target), err)
	}
	return dir, nil
}

func (m *Manager) download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return newErr(CodeDownloadFailed, "build request", "", err)
	}
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return newErr(CodeDownloadFailed,
			"download failed: "+url,
			"Check network/proxy. HTTPS_PROXY may need to be set.", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return newErr(CodeDownloadFailed,
			fmt.Sprintf("download HTTP %d", resp.StatusCode),
			"Verify the URL or pass --version with a known-good release.", nil)
	}

	out, err := os.Create(dest)
	if err != nil {
		return newErr(CodeDownloadFailed, "create staging file", "Check disk space.", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, io.LimitReader(resp.Body, 500<<20)); err != nil {
		return newErr(CodeDownloadFailed, "write to staging", "Check disk space.", err)
	}
	return nil
}

// preflightDisk checks free space on the filesystem hosting the target.
// We need: target binary + .bak (same size) + staging copy → ~3x.
// Threshold is intentionally generous to leave room for journal/log growth
// during the upgrade window.
func preflightDisk(target string) error {
	free, err := freeBytes(filepath.Dir(target))
	if err != nil {
		return nil // can't measure → don't block
	}
	if free < minDestFreeBytes {
		return newErr(CodeDiskInsufficient,
			fmt.Sprintf("only %d MB free on %s, need at least %d MB",
				free/1024/1024, filepath.Dir(target), minDestFreeBytes/1024/1024),
			"Free space — e.g. `rm "+filepath.Dir(target)+"/*.bak-*` "+
				"or `journalctl --vacuum-size=500M`.", nil)
	}
	if tmpFree, err := freeBytes(os.TempDir()); err == nil && tmpFree < minTmpFreeBytes {
		return newErr(CodeTmpInsufficient,
			fmt.Sprintf("only %d MB free on %s, need at least %d MB",
				tmpFree/1024/1024, os.TempDir(), minTmpFreeBytes/1024/1024),
			"Free /tmp space, e.g. `find /tmp -type f -mtime +7 -delete`.", nil)
	}
	return nil
}

// preflightWritable checks the operator can replace the target file. We open
// it for writing without truncating — a permission failure here is the same
// failure os.Rename would hit later, but caught early with a clear message.
func preflightWritable(target string) error {
	dir := filepath.Dir(target)
	probe := filepath.Join(dir, ".upgrade-write-probe")
	f, err := os.Create(probe)
	if err != nil {
		return newErr(CodePermissionDenied,
			"cannot write to "+dir,
			"Re-run with sudo (or as the user that owns "+target+").", err)
	}
	f.Close()
	os.Remove(probe)
	return nil
}

// backupFile copies src to dst, overwriting any existing backup. We use copy
// rather than rename so the original file's inode (and any open file handles
// the running process holds) is preserved until the install.
func backupFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return newErr(CodeBackupFailed, "open original", "", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return newErr(CodeBackupFailed, "create backup file", "Check disk space.", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return newErr(CodeBackupFailed, "copy to backup", "", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return newErr(CodeBackupFailed, "close backup file", "", err)
	}
	return nil
}

// installFile atomically replaces dst with src. Uses rename when src and dst
// are on the same filesystem (the staging dir lives there by design); falls
// back to copy+rename when the rename fails with EXDEV (covers the case where
// --target points to a different mount than os.TempDir()).
func installFile(src, dst string) error {
	tmp := dst + ".upgrade.new"
	// First try a same-FS copy via tmp + rename for atomicity.
	in, err := os.Open(src)
	if err != nil {
		return newErr(CodeReplaceFailed, "open new binary", "", err)
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return newErr(CodeReplaceFailed, "create install tmp", "", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return newErr(CodeReplaceFailed, "copy new binary", "Check disk space.", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return newErr(CodeReplaceFailed, "close install tmp", "", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return newErr(CodeReplaceFailed, "rename install tmp into place", "", err)
	}
	return nil
}

// verifyChecksum reads the file and compares to expected SHA-256.
func verifyChecksum(path, expectedHex string) error {
	if expectedHex == "" {
		return newErr(CodeChecksumMismatch,
			"no expected SHA-256 provided",
			"Pass --sha256 or use the manifest (omit --download-url).", nil)
	}
	expectedHex = strings.TrimPrefix(expectedHex, "sha256:")
	f, err := os.Open(path)
	if err != nil {
		return newErr(CodeChecksumMismatch, "open file for hashing", "", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return newErr(CodeChecksumMismatch, "hash file", "", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expectedHex) {
		return newErr(CodeChecksumMismatch,
			fmt.Sprintf("checksum mismatch: expected %s, got %s", expectedHex, got),
			"File corrupt or tampered. Re-run; if persistent, open a security ticket.", nil)
	}
	return nil
}

// extractBinaryFromZip pulls the etc-collector binary out of a release zip.
func extractBinaryFromZip(zipPath, destPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return newErr(CodeExtractFailed, "open zip", "Re-download — file may be partial.", err)
	}
	defer r.Close()

	want := binaryName()
	for _, f := range r.File {
		if filepath.Base(f.Name) != want || f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return newErr(CodeExtractFailed, "open zip entry", "", err)
		}
		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			rc.Close()
			return newErr(CodeExtractFailed, "create extracted file", "", err)
		}
		_, copyErr := io.Copy(out, rc)
		rc.Close()
		if cerr := out.Close(); cerr != nil && copyErr == nil {
			copyErr = cerr
		}
		if copyErr != nil {
			os.Remove(destPath)
			return newErr(CodeExtractFailed, "copy extracted file", "", copyErr)
		}
		return nil
	}
	return newErr(CodeExtractFailed,
		"binary "+want+" not found in archive",
		"Wrong archive layout — verify the URL points at a release zip.", nil)
}

// sanityCheckBinary runs <new> --version and verifies the output mentions the
// expected version. Catches: wrong arch, corrupt download, format mismatch.
// Timeout is short — `--version` is a constant-time operation.
func sanityCheckBinary(path, expectedVersion string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return newErr(CodeBinaryInvalid,
			"new binary failed to execute --version",
			fmt.Sprintf("Likely wrong OS/arch (expected %s/%s). Re-download.", runtime.GOOS, runtime.GOARCH),
			fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out))))
	}
	if expectedVersion == "" {
		return nil // we have no expectation to match against
	}
	if !strings.Contains(string(out), expectedVersion) {
		return newErr(CodeBinaryInvalid,
			fmt.Sprintf("new binary reports unexpected version (wanted %s)", expectedVersion),
			"Re-download — the file may be the wrong release.",
			fmt.Errorf("got: %s", strings.TrimSpace(string(out))))
	}
	return nil
}

// readBinaryVersion runs <path> --version and returns the version token.
// Returns "" on any error — the caller decides how to handle missing data.
func readBinaryVersion(path string) string {
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	return parseVersionLine(string(out))
}

// parseVersionLine extracts the X.Y.Z token from cobra's `--version` output:
//
//	"etc-collector version 3.1.14 (community)\n"
func parseVersionLine(s string) string {
	s = strings.TrimSpace(s)
	for _, tok := range strings.Fields(s) {
		// Heuristic: a dot-separated token of 3 numeric segments.
		parts := strings.Split(tok, ".")
		if len(parts) < 3 {
			continue
		}
		ok := true
		for _, p := range parts[:3] {
			if _, err := strconv.Atoi(p); err != nil {
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

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "etc-collector.exe"
	}
	return "etc-collector"
}

// nopReporter discards progress events. Used when the caller doesn't supply one.
type nopReporter struct{}

func (nopReporter) Step(int, int, string) {}
func (nopReporter) OK(string)             {}
func (nopReporter) Fail(string)           {}
func (nopReporter) Note(string)           {}

// AsCode extracts the structured Code from any err produced by this package.
// Returns "" when err is not an *Error. Useful for callers that route on Code.
func AsCode(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
