package logger

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/natefinch/lumberjack.v2"
)

func skipIfWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows (os.Chmod only toggles read-only)")
	}
}

func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestLogFileCreatedOwnerOnly — A_004 K7(c). The daemon log used to be created 0644,
// world-readable on a customer domain controller. It holds no passwords, but it does
// hold AD bind DNs, service-account names and the signed update URL (?sig=…).
func TestLogFileCreatedOwnerOnly(t *testing.T) {
	skipIfWindows(t)

	path := filepath.Join(t.TempDir(), "collector.log")
	if _, err := newLogFileWriter(path); err != nil {
		t.Fatalf("newLogFileWriter: %v", err)
	}
	if got := statMode(t, path); got != logFileMode {
		t.Fatalf("new log file is %04o, want %04o", got, logFileMode)
	}
}

// TestLogFileTightenedWhenPreExisting — the trap that matters for the installed fleet.
// os.OpenFile's mode applies only to files it creates, AND lumberjack copies the CURRENT
// file's mode onto every file it rotates into (lumberjack.go openNew: `mode = info.Mode()`).
// So without an explicit chmod, a legacy 0644 log would stay 0644 forever — and would
// propagate 0644 to every rotated file on top of that.
func TestLogFileTightenedWhenPreExisting(t *testing.T) {
	skipIfWindows(t)

	path := filepath.Join(t.TempDir(), "collector.log")
	if err := os.WriteFile(path, []byte("legacy line\n"), 0644); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	// Defeat any umask influence on the seed — we need a genuine 0644 starting point.
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("seed chmod: %v", err)
	}
	if got := statMode(t, path); got != 0644 {
		t.Fatalf("precondition failed: seeded log is %04o, want 0644", got)
	}

	if _, err := newLogFileWriter(path); err != nil {
		t.Fatalf("newLogFileWriter: %v", err)
	}

	if got := statMode(t, path); got != logFileMode {
		t.Fatalf("pre-existing log is %04o, want %04o — an installed collector would keep 0644 forever", got, logFileMode)
	}
	// Tightening must not truncate: the daemon appends to its own history.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "legacy line\n" {
		t.Fatalf("existing log content was lost, got %q", string(data))
	}
}

// TestLogRotationIsBounded — A_004 K7(d). An append-only log on a machine we don't own
// is a disk-exhaustion incident waiting to happen. Bounding it also caps GET_LOGS, whose
// readLastNLines does an unconditional os.ReadFile of the entire file.
func TestLogRotationIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.log")
	w, err := newLogFileWriter(path)
	if err != nil {
		t.Fatalf("newLogFileWriter: %v", err)
	}

	lj, ok := w.(*lumberjack.Logger)
	if !ok {
		t.Fatalf("log writer is %T, want a rotating writer", w)
	}
	if lj.MaxSize <= 0 {
		t.Error("MaxSize must be set — an unbounded log fills the disk of a customer DC")
	}
	if lj.MaxBackups <= 0 && lj.MaxAge <= 0 {
		t.Error("retention must be bounded by count and/or age, otherwise backups accumulate forever")
	}
	if lj.Filename != path {
		t.Errorf("Filename = %q, want %q", lj.Filename, path)
	}
}

// TestNewWithFileFallback_StillFallsBack — the eager create-and-chmod in
// newLogFileWriter exists partly to preserve this contract: lumberjack opens nothing
// until its first Write, so an unwritable path would otherwise be reported as success
// and the daemon would lose its stderr fallback.
func TestNewWithFileFallback_StillFallsBack(t *testing.T) {
	skipIfWindows(t)
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unwritable directory cannot be simulated with permissions")
	}

	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.MkdirAll(dir, 0500); err != nil {
		t.Fatalf("seed dir: %v", err)
	}

	l, actualPath, err := NewWithFileFallback("info", "console", filepath.Join(dir, "collector.log"))
	if err == nil {
		t.Fatal("an unwritable log path must be reported, not silently accepted")
	}
	if actualPath != "" {
		t.Errorf("fallback must report no log file, got %q", actualPath)
	}
	if l == nil {
		t.Fatal("a logger must still be returned so the daemon can keep running")
	}
	l.Info("fallback logger still works")
}
