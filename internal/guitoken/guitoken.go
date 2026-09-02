// Package guitoken manages the GUI access token.
// At install time a random token is generated and shown once.
// Only the SHA-256 hash is persisted; the plaintext is never stored.
package guitoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

const (
	// tokenBytes is the number of random bytes for token generation (32 bytes = 256 bits)
	tokenBytes = 32
	// prefix makes tokens recognizable in logs/pastes
	prefix = "etcsec_gt_"
	// hashFile is the filename for the stored hash
	hashFile = "gui-token.hash"
	// firstRunFile is where a freshly generated token is announced — see AnnounceFirstRun.
	firstRunFile = "gui-token.firstrun"
)

// tokenPattern matches any plaintext token this package could have minted (current
// prefix and length). Exported via RedactTokens so a caller redacting arbitrary text
// — e.g. GET_LOGS, B_135/T_060 — can catch a token this running instance no longer
// holds (already rotated via `gui-token reset`) without duplicating the token's shape
// outside the package that actually defines it.
var tokenPattern = regexp.MustCompile(regexp.QuoteMeta(prefix) + "[0-9a-f]{" + strconv.Itoa(tokenBytes*2) + "}")

// RedactTokens replaces every plaintext token matching this package's format with a
// redaction marker, leaving surrounding text intact.
func RedactTokens(text string) string {
	return tokenPattern.ReplaceAllString(text, "[REDACTED:gui-token]")
}

// Generate creates a new random GUI token and returns the plaintext.
func Generate() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return prefix + hex.EncodeToString(buf), nil
}

// Hash returns the hex-encoded SHA-256 hash of a plaintext token.
func Hash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// SaveHash writes the token hash to the config directory.
func SaveHash(configDir, tokenHash string) error {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	path := filepath.Join(configDir, hashFile)
	if err := os.WriteFile(path, []byte(tokenHash+"\n"), 0600); err != nil {
		return fmt.Errorf("write gui-token hash: %w", err)
	}
	return nil
}

// LoadHash reads the stored token hash from the config directory.
// Returns empty string if no hash file exists.
func LoadHash(configDir string) string {
	path := filepath.Join(configDir, hashFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Trim whitespace/newline
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r' || data[len(data)-1] == ' ') {
		data = data[:len(data)-1]
	}
	return string(data)
}

// Verify checks a plaintext token against the stored hash.
// Returns true if the token matches.
func Verify(storedHash, token string) bool {
	if storedHash == "" || token == "" {
		return false
	}
	h := Hash(token)
	return subtle.ConstantTimeCompare([]byte(h), []byte(storedHash)) == 1
}

// Exists returns true if a gui-token hash file exists in the config directory.
func Exists(configDir string) bool {
	path := filepath.Join(configDir, hashFile)
	_, err := os.Stat(path)
	return err == nil
}

// EnsureHash returns the current token hash for configDir, generating and persisting a
// fresh token if none exists yet.
//
// T_041/B_040: making the admin API fail-closed on a missing hash (see
// api.guiTokenMiddleware) would otherwise lock out every collector upgraded — rather
// than reinstalled — before gui-token existed, which is the default state of the
// installed fleet. Callers that start an HTTP server exposing the admin API must call
// this first so a hash always exists by the time a request can arrive.
//
// plaintext is only non-empty when generated is true — the token is not recoverable
// afterwards, only reset via `gui-token reset`.
func EnsureHash(configDir string) (hash, plaintext string, generated bool, err error) {
	if h := LoadHash(configDir); h != "" {
		return h, "", false, nil
	}
	token, err := Generate()
	if err != nil {
		return "", "", false, fmt.Errorf("generate gui token: %w", err)
	}
	h := Hash(token)
	if err := SaveHash(configDir, h); err != nil {
		return "", "", false, fmt.Errorf("save gui token hash: %w", err)
	}
	return h, token, true, nil
}

// AnnounceFirstRun surfaces a freshly generated token to the operator WITHOUT ever
// passing it to the application's structured logger — B_135 (T_060): that logger also
// writes to collector.log, and the SaaS command channel has a GET_LOGS command that
// returns that file's contents, so concatenating a token into a log message is
// equivalent to handing it to whoever can reach the cloud API for this collector.
//
// Two channels, both bypassing collector.log entirely:
//   - stdout, for a foreground/interactive run and for a systemd unit (journald
//     captures service stdout by default, a channel GET_LOGS cannot reach — it only
//     ever reads the file at logFilePath).
//   - <configDir>/gui-token.firstrun, 0600, for a headless context where stdout isn't
//     visible at all (a Windows service has no attached console). The operator is
//     expected to read it once and delete it; it is not needed for the collector to
//     run.
func AnnounceFirstRun(configDir, token string) error {
	fmt.Println("GUI access token (save this — shown only once, never written to any application log):", token)

	path := filepath.Join(configDir, firstRunFile)
	content := fmt.Sprintf(
		"GUI access token, generated %s.\nDelete this file after copying the token — it is not required for the collector to run.\n\n%s\n",
		time.Now().UTC().Format(time.RFC3339), token,
	)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("write %s: %w", firstRunFile, err)
	}
	// os.WriteFile's mode only applies when it creates the file — tighten explicitly in
	// case a stale file from an older version pre-exists at looser permissions.
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("tighten permissions on %s: %w", firstRunFile, err)
	}
	return nil
}

// Delete removes the gui-token hash file.
func Delete(configDir string) error {
	path := filepath.Join(configDir, hashFile)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete gui-token hash: %w", err)
	}
	return nil
}
