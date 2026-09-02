package saas

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	maxDownloadSize = 500 << 20 // 500 MB
	downloadTimeout = 10 * time.Minute
)

// updateParams holds validated parameters for a collector update
type updateParams struct {
	targetVersion  string
	currentVersion string
	downloadURL    string
	checksum       string // hex-encoded SHA-256
	allowedHost    string // normalized host:port the download must stay on
}

// parseUpdateParams validates and extracts update parameters from command params.
//
// enrolledSaaSURL is the SaaS origin this collector enrolled with (credentials.json
// saasUrl). The update artifact must come from that exact host: the checksum travels
// in the SAME command payload as the URL, so anyone able to forge or alter a command
// controls both and the checksum authenticates nothing on its own. The enrolled host
// is the only thing that ties the artifact to a server we already trust.
func parseUpdateParams(params map[string]interface{}, enrolledSaaSURL string) (*updateParams, error) {
	getString := func(key string) (string, error) {
		v, ok := params[key]
		if !ok {
			return "", fmt.Errorf("missing parameter: %s", key)
		}
		s, ok := v.(string)
		if !ok || s == "" {
			return "", fmt.Errorf("invalid parameter: %s must be a non-empty string", key)
		}
		return s, nil
	}

	targetVersion, err := getString("targetVersion")
	if err != nil {
		return nil, err
	}
	downloadURL, err := getString("downloadUrl")
	if err != nil {
		return nil, err
	}
	checksumRaw, err := getString("checksum")
	if err != nil {
		return nil, err
	}

	// HTTPS + the enrolled SaaS host only (A_004 K1)
	allowedHost, err := validateDownloadURL(downloadURL, enrolledSaaSURL)
	if err != nil {
		return nil, err
	}

	// Parse checksum: expect "sha256:<hex>"
	if !strings.HasPrefix(checksumRaw, "sha256:") {
		return nil, fmt.Errorf("checksum must have sha256: prefix")
	}
	checksumHex := strings.TrimPrefix(checksumRaw, "sha256:")
	if len(checksumHex) != 64 {
		return nil, fmt.Errorf("invalid SHA-256 checksum length")
	}

	currentVersion, _ := getString("currentVersion") // optional

	return &updateParams{
		targetVersion:  targetVersion,
		currentVersion: currentVersion,
		downloadURL:    downloadURL,
		checksum:       checksumHex,
		allowedHost:    allowedHost,
	}, nil
}

// validateDownloadURL enforces that an update artifact is fetched over HTTPS from
// the SaaS host this collector is enrolled with, and returns that normalized host.
//
// The comparison is on the PARSED host, never a string prefix: a prefix check treats
// "https://api.etcsec.com@evil.example/x.zip" and "https://api.etcsec.com.evil.example/x.zip"
// as legitimate. Deliberately not a hardcoded CDN name — the cloud builds downloadUrl
// from SAAS_API_URL (collectors.ts), and on-prem/self-hosted deployments enroll against
// their own host. If a second origin is ever needed, make it a config list.
func validateDownloadURL(downloadURL, enrolledSaaSURL string) (string, error) {
	enrolledSaaSURL = strings.TrimSpace(enrolledSaaSURL)
	if enrolledSaaSURL == "" {
		// Fail closed: with no enrolled origin there is nothing to pin against.
		return "", fmt.Errorf("no enrolled SaaS URL to validate downloadUrl against")
	}
	enrolled, err := url.Parse(enrolledSaaSURL)
	if err != nil || enrolled.Host == "" {
		return "", fmt.Errorf("enrolled SaaS URL is not a valid absolute URL")
	}

	u, err := url.Parse(strings.TrimSpace(downloadURL))
	if err != nil {
		return "", fmt.Errorf("downloadUrl is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("downloadUrl must use HTTPS")
	}
	if u.Host == "" {
		return "", fmt.Errorf("downloadUrl has no host")
	}

	allowedHost := normalizeHost(enrolled)
	if got := normalizeHost(u); got != allowedHost {
		return "", fmt.Errorf("downloadUrl host %q is not the enrolled SaaS host %q", got, allowedHost)
	}
	return allowedHost, nil
}

// normalizeHost returns a lowercased "host:port" with the scheme's default port made
// explicit, so "api.etcsec.com" and "api.etcsec.com:443" compare equal.
func normalizeHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

// stagedUpdate holds paths produced by stageUpdateArtifact: the staging dir,
// the path to the verified+extracted new binary, and the path of the current
// running binary (for backup/install).
type stagedUpdate struct {
	StagingDir    string
	NewBinaryPath string
}

// stageUpdateArtifact downloads, verifies and extracts the update zip into the
// staging directory. It does NOT touch the current binary — that's the caller's
// job (see swapAndExecInPlace on Unix or launchWatcher on Windows).
//
// stagingBase should normally be the directory containing the running binary so
// the later os.Rename into place stays on the same filesystem device (systemd
// hardening with multiple ReadWritePaths exposes each path as a distinct
// bind-mount → renames across them fail EXDEV).
func (d *Daemon) stageUpdateArtifact(params *updateParams, stagingBase string) (*stagedUpdate, error) {
	stagingDir := filepath.Join(stagingBase, ".update-staging")
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}

	archivePath := filepath.Join(stagingDir, "update.zip")
	d.logger.Info("Downloading update", "url", params.downloadURL, "dest", archivePath)
	if err := downloadFile(archivePath, params.downloadURL, params.allowedHost); err != nil {
		os.RemoveAll(stagingDir)
		return nil, fmt.Errorf("download: %w", err)
	}

	d.logger.Info("Verifying checksum")
	if err := verifyChecksum(archivePath, params.checksum); err != nil {
		os.RemoveAll(stagingDir)
		return nil, fmt.Errorf("checksum: %w", err)
	}

	newBinaryPath := filepath.Join(stagingDir, "etc-collector"+binaryExtension())
	d.logger.Info("Extracting binary", "dest", newBinaryPath)
	if err := extractBinaryFromZip(archivePath, newBinaryPath); err != nil {
		os.RemoveAll(stagingDir)
		return nil, fmt.Errorf("extract: %w", err)
	}

	// Free disk space — the archive is no longer needed.
	os.Remove(archivePath)

	return &stagedUpdate{
		StagingDir:    stagingDir,
		NewBinaryPath: newBinaryPath,
	}, nil
}

// downloadFile downloads a URL to a local file with size limit and timeout.
//
// allowedHost is the normalized host:port from validateDownloadURL; every redirect
// hop must stay on it, otherwise the host pinning could be undone by a single 302.
// Today's cloud streams the artifact directly (fleet.ts serves it with
// fs.createReadStream().pipe(res), no redirect), so this changes nothing for the
// current fleet — if a CDN redirect is introduced later, the allowed origins have
// to become a config list here.
func downloadFile(dest, rawURL, allowedHost string) error {
	client := &http.Client{
		Timeout: downloadTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if req.URL.Scheme != "https" || normalizeHost(req.URL) != allowedHost {
				return fmt.Errorf("redirect to %s://%s leaves the enrolled SaaS host %s",
					req.URL.Scheme, req.URL.Host, allowedHost)
			}
			return nil
		},
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		return fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	limited := io.LimitReader(resp.Body, maxDownloadSize+1)
	n, err := io.Copy(f, limited)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if n > maxDownloadSize {
		os.Remove(dest)
		return fmt.Errorf("download exceeds %d MB limit", maxDownloadSize>>20)
	}

	return nil
}

// verifyChecksum checks that a file's SHA-256 matches the expected hex string
func verifyChecksum(filePath, expectedHex string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash: %w", err)
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expectedHex) {
		return fmt.Errorf("mismatch: expected %s, got %s", expectedHex, actual)
	}
	return nil
}

// extractBinaryFromZip extracts the collector binary from a zip archive
// It searches for a file named etc-collector (or etc-collector.exe on Windows)
func extractBinaryFromZip(zipPath, destPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	targetName := "etc-collector" + binaryExtension()

	for _, f := range r.File {
		// Match by base name (archive may have a directory prefix)
		if filepath.Base(f.Name) != targetName {
			continue
		}
		if f.FileInfo().IsDir() {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open entry %s: %w", f.Name, err)
		}
		defer rc.Close()

		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return fmt.Errorf("create dest: %w", err)
		}
		defer out.Close()

		if _, err := io.Copy(out, rc); err != nil {
			return fmt.Errorf("copy: %w", err)
		}
		return nil
	}

	return fmt.Errorf("binary %s not found in archive", targetName)
}

// binaryExtension returns the platform-appropriate binary extension
func binaryExtension() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
