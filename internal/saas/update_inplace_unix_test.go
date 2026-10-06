//go:build !windows

package saas

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestIsCrossDevice(t *testing.T) {
	if !isCrossDevice(syscall.EXDEV) {
		t.Errorf("bare EXDEV should be recognised as cross-device")
	}
	// rename() returns *os.LinkError{Op: "rename", Err: syscall.EXDEV}.
	wrapped := &os.LinkError{Op: "rename", Old: "a", New: "b", Err: syscall.EXDEV}
	if !isCrossDevice(wrapped) {
		t.Errorf("wrapped LinkError should be recognised as cross-device")
	}
	if isCrossDevice(syscall.ENOENT) {
		t.Errorf("ENOENT should not be classified as cross-device")
	}
	if isCrossDevice(nil) {
		t.Errorf("nil should not be cross-device")
	}
	if isCrossDevice(errors.New("some other error")) {
		t.Errorf("random error should not be cross-device")
	}
}

func TestCopyFileContents(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	payload := []byte("fake etc-collector binary content")
	if err := os.WriteFile(src, payload, 0755); err != nil {
		t.Fatal(err)
	}
	if err := copyFileContents(src, dst); err != nil {
		t.Fatalf("copyFileContents: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Errorf("content mismatch: got %q want %q", got, payload)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("mode not preserved: got %o want 0755", info.Mode().Perm())
	}
}

// TestInstallBinary_SameDevice verifies the fast-path (plain rename) succeeds
// when src and dst are on the same filesystem. The EXDEV fallback path is not
// unit-tested because it requires two separate filesystems (typically tmpfs),
// which isn't portable to a hermetic test environment.
func TestInstallBinary_SameDevice(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := installBinary(src, dst); err != nil {
		t.Fatalf("installBinary same-device: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Errorf("dst missing after install: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("src should be removed after install, got err=%v", err)
	}
}
