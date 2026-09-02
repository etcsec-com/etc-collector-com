package saas

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func skipIfWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows (os.Chmod only toggles read-only)")
	}
}

// TestSecureDir_TightensPreExistingDirectory — A_004 K7(b). The whole point of the fix:
// os.MkdirAll's mode is ignored when the directory already exists, so simply changing
// 0755 to 0700 at the call site would have fixed new installs and left every collector
// already in the field at 0755 forever. This test therefore STARTS from a 0755 directory.
func TestSecureDir_TightensPreExistingDirectory(t *testing.T) {
	skipIfWindows(t)

	dir := filepath.Join(t.TempDir(), "etc-collector")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	// Defeat any umask influence on the seed — we need a genuine 0755 starting point.
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatalf("seed chmod: %v", err)
	}
	if got := statMode(t, dir); got != 0755 {
		t.Fatalf("precondition failed: seeded dir is %04o, want 0755", got)
	}

	if err := SecureDir(dir); err != nil {
		t.Fatalf("SecureDir: %v", err)
	}
	if got := statMode(t, dir); got != SecureDirMode {
		t.Fatalf("pre-existing directory is %04o, want %04o — an installed collector would keep 0755 forever", got, SecureDirMode)
	}
}

func TestSecureDir_CreatesMissingDirectory(t *testing.T) {
	skipIfWindows(t)

	dir := filepath.Join(t.TempDir(), "nested", "etc-collector")
	if err := SecureDir(dir); err != nil {
		t.Fatalf("SecureDir: %v", err)
	}
	if got := statMode(t, dir); got != SecureDirMode {
		t.Fatalf("created directory is %04o, want %04o", got, SecureDirMode)
	}
}

// TestSecureFile_TightensPreExistingFile — same trap on the file side: os.WriteFile's
// mode applies only when it creates the file.
func TestSecureFile_TightensPreExistingFile(t *testing.T) {
	skipIfWindows(t)

	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("seed chmod: %v", err)
	}

	if err := SecureFile(path); err != nil {
		t.Fatalf("SecureFile: %v", err)
	}
	if got := statMode(t, path); got != SecureFileMode {
		t.Fatalf("pre-existing file is %04o, want %04o", got, SecureFileMode)
	}
}

func TestSecureFile_MissingFileIsNotAnError(t *testing.T) {
	if err := SecureFile(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("a missing file has nothing to protect, got: %v", err)
	}
}

// TestCredentialStoreSavesOwnerOnly — end-to-end on the real writer: the config
// directory ends up 0700 even though it pre-existed at 0755, and credentials.json is
// 0600. These are the files holding ApiKey / BindPassword / ClientSecret.
func TestCredentialStoreSavesOwnerOnly(t *testing.T) {
	skipIfWindows(t)

	dir := filepath.Join(t.TempDir(), "cfg")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatalf("seed chmod: %v", err)
	}

	store := NewCredentialStore(dir)
	if err := store.Save(&Credentials{CollectorID: "c1", ApiKey: "secret-key", SaaSURL: "https://api.etcsec.com"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if got := statMode(t, dir); got != SecureDirMode {
		t.Errorf("config dir is %04o, want %04o", got, SecureDirMode)
	}
	if got := statMode(t, store.Path()); got != SecureFileMode {
		t.Errorf("credentials.json is %04o, want %04o", got, SecureFileMode)
	}
}

// TestNoRelativeFallbackForSecrets — A_004 K7(e). Where the SaaS API key, the AD bind
// password and the Azure clientSecret land must never depend on the process's working
// directory. With no resolvable location, the collector must fail loudly.
func TestNoRelativeFallbackForSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows resolves to an absolute ProgramData path with no fallback branch")
	}

	// Point both env overrides away. t.Setenv restores the previous values automatically.
	t.Setenv("ETCSEC_CONFIG_DIR", "")
	t.Setenv("ETCSEC_DATA_DIR", "")

	// Force the well-known paths to somewhere guaranteed absent. Without this the test
	// would take its "the path exists" branch on any machine that has run the installer
	// — including this one — and never exercise the fallback at all.
	absent := filepath.Join(t.TempDir(), "definitely-not-here")
	origConfig, origData := linuxConfigDirPath, linuxDataDirPath
	linuxConfigDirPath, linuxDataDirPath = absent, absent
	t.Cleanup(func() { linuxConfigDirPath, linuxDataDirPath = origConfig, origData })

	for _, tc := range []struct {
		name    string
		resolve func() (string, error)
	}{
		{"config", DefaultConfigDir},
		{"data", DefaultDataDir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := tc.resolve()

			// The old code returned "./data" here — secrets landing wherever the
			// process happened to be started from.
			if err == nil {
				t.Fatalf("expected an explicit error, got directory %q", dir)
			}
			if dir != "" {
				t.Fatalf("a failed resolution must return no path, got %q", dir)
			}
			if strings.Contains(err.Error(), "./data") {
				t.Errorf("the error must not suggest the relative path it replaced: %v", err)
			}
		})
	}
}

// TestWellKnownPathIsUsedWhenPresent — the other half: when the well-known directory
// does exist, that is the answer and no error is raised.
func TestWellKnownPathIsUsedWhenPresent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows resolves to an absolute ProgramData path with no probe")
	}

	t.Setenv("ETCSEC_CONFIG_DIR", "")
	present := t.TempDir() // exists by construction

	orig := linuxConfigDirPath
	linuxConfigDirPath = present
	t.Cleanup(func() { linuxConfigDirPath = orig })

	dir, err := DefaultConfigDir()
	if err != nil {
		t.Fatalf("an existing well-known path must resolve: %v", err)
	}
	if dir != present {
		t.Fatalf("got %q, want %q", dir, present)
	}
}

// TestExplicitDirsAlwaysWin — the escape hatch the error message points at must work.
func TestExplicitDirsAlwaysWin(t *testing.T) {
	t.Setenv("ETCSEC_CONFIG_DIR", "/tmp/etcsec-explicit-config")
	t.Setenv("ETCSEC_DATA_DIR", "/tmp/etcsec-explicit-data")

	dir, err := DefaultConfigDir()
	if err != nil || dir != "/tmp/etcsec-explicit-config" {
		t.Fatalf("ETCSEC_CONFIG_DIR ignored: got %q, err %v", dir, err)
	}
	dir, err = DefaultDataDir()
	if err != nil || dir != "/tmp/etcsec-explicit-data" {
		t.Fatalf("ETCSEC_DATA_DIR ignored: got %q, err %v", dir, err)
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
