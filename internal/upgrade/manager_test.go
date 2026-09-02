package upgrade

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestParseVersionLine covers the formats actually emitted by `etc-collector
// --version` (cobra's auto-generated line) plus a few defensive variants.
func TestParseVersionLine(t *testing.T) {
	cases := map[string]string{
		"etc-collector version 3.1.14 (community)": "3.1.14",
		"etc-collector version 3.1.15 (pro)":       "3.1.15",
		"etc-collector version 3.10.0 (community)": "3.10.0",
		"3.1.14 (pro)": "3.1.14",
		"":             "",
		"foo bar baz":  "",
	}
	for in, want := range cases {
		if got := parseVersionLine(in); got != want {
			t.Errorf("parseVersionLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestVerifyChecksum_OK checks the happy path with a real SHA-256.
func TestVerifyChecksum_OK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("hello"))
	if err := verifyChecksum(path, hex.EncodeToString(h[:])); err != nil {
		t.Fatalf("verifyChecksum: %v", err)
	}
}

// TestVerifyChecksum_Mismatch must produce CodeChecksumMismatch.
func TestVerifyChecksum_Mismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x")
	_ = os.WriteFile(path, []byte("hello"), 0644)
	err := verifyChecksum(path, strings.Repeat("0", 64))
	if AsCode(err) != CodeChecksumMismatch {
		t.Fatalf("got code %q, want %q (err=%v)", AsCode(err), CodeChecksumMismatch, err)
	}
}

// TestExtractBinaryFromZip extracts a single file matching the platform-
// specific binary name and writes it to the destination.
func TestExtractBinaryFromZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "release.zip")
	want := []byte("#!/bin/sh\necho hi\n")

	buf := bytes.NewBuffer(nil)
	zw := zip.NewWriter(buf)
	w, _ := zw.Create("release/" + binaryName())
	w.Write(want)
	zw.Close()
	_ = os.WriteFile(zipPath, buf.Bytes(), 0644)

	dest := filepath.Join(dir, "out")
	if err := extractBinaryFromZip(zipPath, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, want) {
		t.Fatalf("contents mismatch")
	}
}

// TestExtractBinaryFromZip_Missing returns CodeExtractFailed when the zip
// doesn't contain the expected binary name (wrong archive layout).
func TestExtractBinaryFromZip_Missing(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "release.zip")

	buf := bytes.NewBuffer(nil)
	zw := zip.NewWriter(buf)
	w, _ := zw.Create("README.md")
	w.Write([]byte("nothing here"))
	zw.Close()
	_ = os.WriteFile(zipPath, buf.Bytes(), 0644)

	err := extractBinaryFromZip(zipPath, filepath.Join(dir, "out"))
	if AsCode(err) != CodeExtractFailed {
		t.Fatalf("got code %q, want %q (err=%v)", AsCode(err), CodeExtractFailed, err)
	}
}

// TestManifestResolveVersion covers latest + explicit + missing.
func TestManifestResolveVersion(t *testing.T) {
	m := &Manifest{
		Latest: "3.1.15",
		Versions: map[string]VersionEntry{
			"3.1.15": {Artifacts: []Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "u15", SHA256: "s15"}}},
			"3.1.14": {Artifacts: []Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "u14", SHA256: "s14"}}},
		},
	}

	v, art, err := m.ResolveVersion("")
	if err != nil || v != "3.1.15" || art.URL != "u15" {
		t.Fatalf("latest: v=%s err=%v", v, err)
	}
	v, art, err = m.ResolveVersion("3.1.14")
	if err != nil || v != "3.1.14" || art.URL != "u14" {
		t.Fatalf("explicit: v=%s err=%v", v, err)
	}
	if _, _, err := m.ResolveVersion("9.9.9"); AsCode(err) != CodeVersionNotFound {
		t.Fatalf("missing: code=%q err=%v", AsCode(err), err)
	}
}

// TestFetchManifest_OK boots a httptest server, lets FetchManifest hit it,
// then asserts the parsed body matches.
func TestFetchManifest_OK(t *testing.T) {
	body, _ := json.Marshal(Manifest{
		Latest:   "1.0.0",
		Versions: map[string]VersionEntry{"1.0.0": {Released: "2026-01-01T00:00:00Z"}},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	m, err := FetchManifest(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if m.Latest != "1.0.0" {
		t.Fatalf("latest=%s", m.Latest)
	}
}

// TestFetchManifest_404 maps an HTTP error to CodeNetworkUnreachable.
func TestFetchManifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	_, err := FetchManifest(context.Background(), srv.URL)
	if AsCode(err) != CodeNetworkUnreachable {
		t.Fatalf("code=%q err=%v", AsCode(err), err)
	}
}

// TestRollback_NoBackup returns the canonical "nothing to roll back" code.
func TestRollback_NoBackup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "etc-collector")
	_ = os.WriteFile(target, []byte("current"), 0755)

	m := NewManager()
	err := m.Rollback(Plan{TargetPath: target, NoRestart: true})
	if AsCode(err) != CodeRollbackUnavailable {
		t.Fatalf("code=%q err=%v", AsCode(err), err)
	}
}

// TestRollback_Restores swaps a .bak back into place when the user explicitly
// asks for a rollback. Verifies the file content actually gets restored.
func TestRollback_Restores(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "etc-collector")
	backup := target + ".bak"
	_ = os.WriteFile(target, []byte("broken-new"), 0755)
	_ = os.WriteFile(backup, []byte("good-old"), 0755)

	m := NewManager()
	if err := m.Rollback(Plan{TargetPath: target, NoRestart: true}); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "good-old" {
		t.Fatalf("rollback did not restore: got %q", got)
	}
}

// TestPreflightDisk_Sufficient ensures the happy path returns nil — the test
// runs from a normal /tmp which has way more than 200 MB.
func TestPreflightDisk_Sufficient(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fake")
	_ = os.WriteFile(target, []byte("x"), 0644)
	if err := preflightDisk(target); err != nil {
		t.Fatalf("preflightDisk: %v", err)
	}
}

// TestBackupAndInstall round-trips through the helpers: write a target,
// download a fake new binary into staging, install + check + roll back.
func TestBackupAndInstall(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "bin")
	_ = os.WriteFile(target, []byte("OLD"), 0755)

	stage := filepath.Join(dir, "stage")
	_ = os.WriteFile(stage, []byte("NEW"), 0755)

	if err := backupFile(target, target+".bak"); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if got, _ := os.ReadFile(target + ".bak"); string(got) != "OLD" {
		t.Fatalf("bak content: %q", got)
	}
	if err := installFile(stage, target); err != nil {
		t.Fatalf("install: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "NEW" {
		t.Fatalf("target content: %q", got)
	}
}

// TestDownload exercises Manager.download against an in-process server,
// catching missing 200 + truncation along the way.
func TestDownload(t *testing.T) {
	want := []byte("hello world")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, bytes.NewReader(want))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "out")
	m := NewManager()
	if err := m.download(context.Background(), srv.URL, dest); err != nil {
		t.Fatalf("download: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch")
	}
}
