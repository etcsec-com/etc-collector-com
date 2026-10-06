package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/scanner"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withGitHubBaseURL points githubBaseURL at a test server for the duration
// of the test, restoring the real value on cleanup.
func withGitHubBaseURL(t *testing.T, url string) {
	t.Helper()
	orig := githubBaseURL
	githubBaseURL = url
	t.Cleanup(func() { githubBaseURL = orig })
}

// TestNoAPIGitHubUsage is a regression guard for a deliberate design decision:
// the unauthenticated REST API is capped at 60 req/h/IP and would let one
// customer's collector fleet rate-limit itself behind a single NAT. No
// identifier or string literal in this package's CODE may reference
// api.github.com - comments are allowed to name it (this file's own doc
// comments do, to explain why it's avoided).
func TestNoAPIGitHubUsage(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if sourceReferencesOutsideComments(body, "api.github.com") {
			t.Errorf("%s references api.github.com outside a comment - the unauthenticated REST API is rate-limited to 60 req/h/IP; use the github.com HTML redirects instead", e.Name())
		}
	}
}

// sourceReferencesOutsideComments reports whether substr appears in any
// non-comment token (identifier, string literal, ...) of the given Go
// source.
func sourceReferencesOutsideComments(src []byte, substr string) bool {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, nil, scanner.ScanComments)
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.COMMENT {
			continue
		}
		if strings.Contains(lit, substr) {
			return true
		}
	}
	return false
}

// TestResolveLatestTag_OK exercises the single-redirect-hop path against a
// fake server: HEAD /releases/latest -> 302 with Location carrying the tag.
func TestResolveLatestTag_OK(t *testing.T) {
	var gotMethod string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		if r.URL.Path != "/etcsec-com/etc-collector-com/releases/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		http.Redirect(w, r, srv.URL+"/etcsec-com/etc-collector-com/releases/tag/v9.9.9", http.StatusFound)
	}))
	defer srv.Close()
	withGitHubBaseURL(t, srv.URL)

	tag, err := resolveLatestTag(context.Background(), &http.Client{}, "etcsec-com/etc-collector-com")
	if err != nil {
		t.Fatalf("resolveLatestTag: %v", err)
	}
	if tag != "v9.9.9" {
		t.Fatalf("tag = %q, want v9.9.9", tag)
	}
	if gotMethod != http.MethodHead {
		t.Fatalf("method = %q, want HEAD (metadata only, no HTML body download)", gotMethod)
	}
}

// TestResolveLatestTag_NotARedirect surfaces a clear error when github.com
// doesn't answer with the expected 302 (outage, moved repo, ...).
func TestResolveLatestTag_NotARedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withGitHubBaseURL(t, srv.URL)

	_, err := resolveLatestTag(context.Background(), &http.Client{}, "etcsec-com/etc-collector-com")
	if AsCode(err) != CodeNetworkUnreachable {
		t.Fatalf("code=%q err=%v", AsCode(err), err)
	}
}

// TestFetchChecksums_OK parses the standard sha256sum output format.
func TestFetchChecksums_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/etcsec-com/etc-collector-com/releases/download/v9.9.9/checksums.sha256"
		if r.URL.Path != want {
			t.Errorf("path = %s, want %s", r.URL.Path, want)
		}
		fmt.Fprintf(w, "%s  etc-collector-9.9.9-linux-amd64.tar.gz\n", strings.Repeat("a", 64))
		fmt.Fprintf(w, "%s  etc-collector-9.9.9-windows-amd64.zip\n", strings.Repeat("b", 64))
	}))
	defer srv.Close()
	withGitHubBaseURL(t, srv.URL)

	sums, err := fetchChecksums(context.Background(), &http.Client{}, "etcsec-com/etc-collector-com", "v9.9.9")
	if err != nil {
		t.Fatalf("fetchChecksums: %v", err)
	}
	if sums["etc-collector-9.9.9-linux-amd64.tar.gz"] != strings.Repeat("a", 64) {
		t.Fatalf("linux-amd64 sha = %q", sums["etc-collector-9.9.9-linux-amd64.tar.gz"])
	}
	if sums["etc-collector-9.9.9-windows-amd64.zip"] != strings.Repeat("b", 64) {
		t.Fatalf("windows-amd64 sha = %q", sums["etc-collector-9.9.9-windows-amd64.zip"])
	}
}

// TestResolveGitHubRelease_ExplicitVersion pins a version without ever
// hitting /releases/latest - no redirect resolution needed.
func TestResolveGitHubRelease_ExplicitVersion(t *testing.T) {
	hitLatest := false
	mux := http.NewServeMux()
	mux.HandleFunc("/etcsec-com/etc-collector-com/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		hitLatest = true
		w.WriteHeader(http.StatusNotFound)
	})
	asset, err := releaseAssetName("9.9.8", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skipf("platform %s/%s not published: %v", runtime.GOOS, runtime.GOARCH, err)
	}
	mux.HandleFunc("/etcsec-com/etc-collector-com/releases/download/v9.9.8/checksums.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", strings.Repeat("c", 64), asset)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	withGitHubBaseURL(t, srv.URL)

	version, url, sha, err := resolveGitHubRelease(context.Background(), &http.Client{}, "9.9.8")
	if err != nil {
		t.Fatalf("resolveGitHubRelease: %v", err)
	}
	if hitLatest {
		t.Fatalf("explicit --version hit /releases/latest - should resolve the tag directly")
	}
	if version != "9.9.8" {
		t.Fatalf("version = %q, want 9.9.8", version)
	}
	if sha != strings.Repeat("c", 64) {
		t.Fatalf("sha = %q", sha)
	}
	wantURL := srv.URL + "/etcsec-com/etc-collector-com/releases/download/v9.9.8/" + asset
	if url != wantURL {
		t.Fatalf("url = %q, want %q", url, wantURL)
	}
}

// TestCheckOnly_GitHubRelease_NoManifestNeeded is the direct regression test
// for a bug where get.etcsec.com/downloads/manifest.json (and
// latest.json) 404ed while the GitHub release itself was live and healthy,
// so `upgrade --check` reported UPGRADE_NETWORK_UNREACHABLE for a version
// that was actually available. This fake server exposes ONLY the two
// redirect-shaped endpoints (/releases/latest, checksums.sha256) - there is
// no manifest.json route at all - proving the default path never needs one.
func TestCheckOnly_GitHubRelease_NoManifestNeeded(t *testing.T) {
	asset, err := releaseAssetName("3.2.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skipf("platform %s/%s not published: %v", runtime.GOOS, runtime.GOARCH, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/etcsec-com/etc-collector-com/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/etcsec-com/etc-collector-com/releases/tag/v3.2.0", http.StatusFound)
	})
	mux.HandleFunc("/etcsec-com/etc-collector-com/releases/download/v3.2.0/checksums.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", strings.Repeat("d", 64), asset)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	withGitHubBaseURL(t, srv.URL)

	dir := t.TempDir()
	target := filepath.Join(dir, binaryName())
	writeFakeVersionBinary(t, target, "3.1.14")

	m := NewManager()
	current, latest, err := m.CheckOnly(context.Background(), Plan{TargetPath: target})
	if err != nil {
		t.Fatalf("CheckOnly: %v (a missing manifest.json must not block this)", err)
	}
	if current != "3.1.14" {
		t.Fatalf("current = %q, want 3.1.14", current)
	}
	if latest != "3.2.0" {
		t.Fatalf("latest = %q, want 3.2.0", latest)
	}
}

// TestRun_GitHubRelease_RealUpgrade drives the full 8-step Run() against a
// fake GitHub-shaped server: an old binary sees a newer release and actually
// installs it - not just a version-string comparison. Proves both that the
// GitHub-direct source works end to end and that SHA-256 verification still
// runs on the downloaded archive.
func TestRun_GitHubRelease_RealUpgrade(t *testing.T) {
	asset, err := releaseAssetName("3.2.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skipf("platform %s/%s not published: %v", runtime.GOOS, runtime.GOARCH, err)
	}
	archiveBytes := buildTarGzBinary(t, "etc-collector-3.2.0/"+binaryName(), fakeVersionScript("3.2.0"))
	sum := sha256.Sum256(archiveBytes)
	shaHex := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/etcsec-com/etc-collector-com/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/etcsec-com/etc-collector-com/releases/tag/v3.2.0", http.StatusFound)
	})
	mux.HandleFunc("/etcsec-com/etc-collector-com/releases/download/v3.2.0/checksums.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", shaHex, asset)
	})
	mux.HandleFunc("/etcsec-com/etc-collector-com/releases/download/v3.2.0/"+asset, func(w http.ResponseWriter, r *http.Request) {
		w.Write(archiveBytes)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	withGitHubBaseURL(t, srv.URL)

	dir := t.TempDir()
	target := filepath.Join(dir, binaryName())
	writeFakeVersionBinary(t, target, "3.1.14")

	m := NewManager()
	res, err := m.Run(context.Background(), Plan{
		TargetPath:     target,
		CurrentVersion: "3.1.14",
		NoRestart:      true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Skipped {
		t.Fatalf("upgrade was skipped, want a real 3.1.14 -> 3.2.0 switch")
	}
	if res.From != "3.1.14" || res.To != "3.2.0" {
		t.Fatalf("From=%q To=%q, want 3.1.14 -> 3.2.0", res.From, res.To)
	}

	got, err := exec.Command(target, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("run installed binary: %v", err)
	}
	if !strings.Contains(string(got), "3.2.0") {
		t.Fatalf("installed binary reports %q, want a string containing 3.2.0", got)
	}
}

// TestRun_GitHubRelease_ChecksumMismatch_Aborts proves the mismatch case:
// the archive that is actually served does not match what checksums.sha256
// declares (corruption/tamper). The old binary must be left untouched.
func TestRun_GitHubRelease_ChecksumMismatch_Aborts(t *testing.T) {
	asset, err := releaseAssetName("3.2.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skipf("platform %s/%s not published: %v", runtime.GOOS, runtime.GOARCH, err)
	}
	archiveBytes := buildTarGzBinary(t, "etc-collector-3.2.0/"+binaryName(), fakeVersionScript("3.2.0"))

	mux := http.NewServeMux()
	mux.HandleFunc("/etcsec-com/etc-collector-com/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/etcsec-com/etc-collector-com/releases/tag/v3.2.0", http.StatusFound)
	})
	mux.HandleFunc("/etcsec-com/etc-collector-com/releases/download/v3.2.0/checksums.sha256", func(w http.ResponseWriter, r *http.Request) {
		// Declares a checksum that does NOT match the bytes actually served
		// below - simulates a corrupted or tampered mirror.
		fmt.Fprintf(w, "%s  %s\n", strings.Repeat("0", 64), asset)
	})
	mux.HandleFunc("/etcsec-com/etc-collector-com/releases/download/v3.2.0/"+asset, func(w http.ResponseWriter, r *http.Request) {
		w.Write(archiveBytes)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	withGitHubBaseURL(t, srv.URL)

	dir := t.TempDir()
	target := filepath.Join(dir, binaryName())
	writeFakeVersionBinary(t, target, "3.1.14")
	before, _ := os.ReadFile(target)

	m := NewManager()
	_, err = m.Run(context.Background(), Plan{
		TargetPath:     target,
		CurrentVersion: "3.1.14",
		NoRestart:      true,
	})
	if AsCode(err) != CodeChecksumMismatch {
		t.Fatalf("code=%q err=%v, want CodeChecksumMismatch", AsCode(err), err)
	}
	after, _ := os.ReadFile(target)
	if !bytes.Equal(before, after) {
		t.Fatalf("target binary was modified despite a checksum mismatch")
	}
}

// TestExtractBinaryFromTarGz covers the archive format the public GitHub
// release actually publishes for linux/darwin (release.yml) - .tar.gz, not
// .zip. Before this, extractBinaryFromZip was the only extractor, so this
// format could not be installed at all.
func TestExtractBinaryFromTarGz(t *testing.T) {
	dir := t.TempDir()
	want := []byte("#!/bin/sh\necho hi\n")
	archivePath := filepath.Join(dir, "release.tar.gz")
	os.WriteFile(archivePath, buildTarGzBinary(t, "release/"+binaryName(), want), 0644)

	dest := filepath.Join(dir, "out")
	if err := extractBinaryFromTarGz(archivePath, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, want) {
		t.Fatalf("contents mismatch")
	}
}

// TestExtractBinaryFromTarGz_Missing mirrors TestExtractBinaryFromZip_Missing
// for the tar.gz path.
func TestExtractBinaryFromTarGz_Missing(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "release.tar.gz")
	os.WriteFile(archivePath, buildTarGzBinary(t, "README.md", []byte("nothing here")), 0644)

	err := extractBinaryFromTarGz(archivePath, filepath.Join(dir, "out"))
	if AsCode(err) != CodeExtractFailed {
		t.Fatalf("got code %q, want %q (err=%v)", AsCode(err), CodeExtractFailed, err)
	}
}

// TestArchiveExt_DispatchesOnURL checks the staging filename picks the right
// extractor for each source shape release.yml actually publishes.
func TestArchiveExt_DispatchesOnURL(t *testing.T) {
	cases := map[string]string{
		"https://x/etc-collector-3.2.0-linux-amd64.tar.gz": ".tar.gz",
		"https://x/etc-collector-3.2.0-windows-amd64.zip":  ".zip",
		"https://mirror.local/downloads/etc-collector.tgz": ".tar.gz",
		"https://mirror.local/downloads/manifest-artifact": ".zip", // unknown ext: historical zip default
	}
	for url, want := range cases {
		if got := archiveExt(url); got != want {
			t.Errorf("archiveExt(%q) = %q, want %q", url, got, want)
		}
	}
}

// ─── test helpers ───────────────────────────────────────────────────────

func buildTarGzBinary(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	gz := gzip.NewWriter(buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: name, Mode: 0755, Size: int64(len(content))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func fakeVersionScript(version string) []byte {
	return []byte("#!/bin/sh\necho \"etc-collector version " + version + " (test)\"\n")
}

func writeFakeVersionBinary(t *testing.T, path, version string) {
	t.Helper()
	if err := os.WriteFile(path, fakeVersionScript(version), 0755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
}
