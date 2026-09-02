package saas

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Credentials stores authentication and configuration from SaaS enrollment
type Credentials struct {
	CollectorID string          `json:"collectorId"`
	ApiKey      string          `json:"apiKey"`
	SaaSURL     string          `json:"saasUrl"`
	Config      CollectorConfig `json:"config"`

	// CommandSigningPublicKeys — K3 (T_045). The Ed25519 verification keys this
	// collector currently trusts for command signatures. Persisted so a restart
	// doesn't drop back to the unverified path while waiting for the next
	// key-bearing poll/health response. See checkCommandSignature.
	CommandSigningPublicKeys []CommandSigningKey `json:"commandSigningPublicKeys,omitempty"`
}

// Well-known Unix locations. Named so the "does it exist" probe and the error message
// can never drift apart. Variables rather than constants purely so the tests can point
// them at a path that is guaranteed absent — otherwise the "no relative fallback"
// assertion silently skips itself on any machine where /etc/etc-collector happens to
// exist, which is every developer machine that has ever run the installer.
var (
	linuxConfigDirPath = "/etc/etc-collector"
	linuxDataDirPath   = "/var/lib/etc-collector"
)

// CredentialStore manages persistent credentials
type CredentialStore struct {
	path string
}

// NewCredentialStore creates a new credential store in the given config directory
func NewCredentialStore(configDir string) *CredentialStore {
	return &CredentialStore{
		path: filepath.Join(configDir, "credentials.json"),
	}
}

// Save persists credentials to disk using atomic write (temp + rename).
// A backup (.bak) of the previous file is kept for crash recovery.
func (s *CredentialStore) Save(creds *Credentials) error {
	// SecureDir, not a bare MkdirAll: on an existing install the directory is already
	// there at 0755 and MkdirAll's mode would be ignored (A_004 K7(b)).
	dir := filepath.Dir(s.path)
	if err := SecureDir(dir); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	// Write to temp file first (atomic: avoids corrupted file on crash mid-write)
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, SecureFileMode); err != nil {
		return fmt.Errorf("write credentials tmp: %w", err)
	}
	// WriteFile's mode only applies when it creates the file — a leftover .tmp from an
	// interrupted write would keep its old mode and then be renamed into place.
	if err := SecureFile(tmpPath); err != nil {
		return fmt.Errorf("secure credentials tmp: %w", err)
	}

	// Backup current file before overwriting (for crash recovery)
	if _, err := os.Stat(s.path); err == nil {
		_ = os.Rename(s.path, s.path+".bak")
	}

	// Atomic rename
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("rename credentials: %w", err)
	}

	return nil
}

// Load reads credentials from disk. If the main file is corrupted,
// it falls back to the .bak backup file automatically.
func (s *CredentialStore) Load() (*Credentials, error) {
	creds, err := s.loadFile(s.path)
	if err == nil {
		return creds, nil
	}

	// Main file missing or corrupted — try backup
	if backupCreds, backupErr := s.loadFile(s.path + ".bak"); backupErr == nil {
		// Restore backup as main file
		_ = s.Save(backupCreds)
		return backupCreds, nil
	}

	// If main file simply doesn't exist, return nil (not enrolled)
	if os.IsNotExist(err) {
		return nil, nil
	}

	return nil, err
}

func (s *CredentialStore) loadFile(path string) (*Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("unmarshal credentials (%s): %w", path, err)
	}

	return &creds, nil
}

// Delete removes stored credentials
func (s *CredentialStore) Delete() error {
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete credentials: %w", err)
	}
	return nil
}

// Exists returns true if credentials are stored
func (s *CredentialStore) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Path returns the credentials file path
func (s *CredentialStore) Path() string {
	return s.path
}

// DataDir returns the directory containing credentials (used for staging updates)
func (s *CredentialStore) DataDir() string {
	return filepath.Dir(s.path)
}

// DefaultConfigDir returns the platform-appropriate config directory.
//
// A_004 K7(e): this used to fall back to "./data" — a path relative to the process's
// working directory — when /etc/etc-collector was absent. Where the SaaS API key, the
// AD bind password and the Azure clientSecret landed therefore depended on where the
// binary happened to be launched from. A clear error beats secrets dropped at random,
// so an unresolvable directory is now a failure with an actionable message.
func DefaultConfigDir() (string, error) {
	if dir := os.Getenv("ETCSEC_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	switch runtime.GOOS {
	case "windows":
		return `C:\ProgramData\ETCSec\etc-collector`, nil
	default:
		if _, err := os.Stat(linuxConfigDirPath); err == nil {
			return linuxConfigDirPath, nil
		}
		return "", fmt.Errorf("no config directory: %s does not exist. Run 'etc-collector install' "+
			"first, or set ETCSEC_CONFIG_DIR / pass --config-dir to choose an explicit location "+
			"(refusing to write credentials to a path relative to the current directory)",
			linuxConfigDirPath)
	}
}

// DefaultDataDir returns the platform-appropriate data directory. Same fallback removal
// as DefaultConfigDir — see A_004 K7(e).
func DefaultDataDir() (string, error) {
	if dir := os.Getenv("ETCSEC_DATA_DIR"); dir != "" {
		return dir, nil
	}
	switch runtime.GOOS {
	case "windows":
		return `C:\ProgramData\ETCSec\etc-collector`, nil
	default:
		if _, err := os.Stat(linuxDataDirPath); err == nil {
			return linuxDataDirPath, nil
		}
		return "", fmt.Errorf("no data directory: %s does not exist. Run 'etc-collector install' "+
			"first, or set ETCSEC_DATA_DIR (refusing to write state to a path relative to the "+
			"current directory)", linuxDataDirPath)
	}
}
