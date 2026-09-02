package saas

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"127.0.0.1", "localhost", "::1", "127.0.0.2"}
	notLoopback := []string{"0.0.0.0", "", "10.0.0.5", "192.168.1.1", "dc01.corp.local"}

	for _, h := range loopback {
		if !IsLoopbackHost(h) {
			t.Errorf("IsLoopbackHost(%q) = false, want true", h)
		}
	}
	for _, h := range notLoopback {
		if IsLoopbackHost(h) {
			t.Errorf("IsLoopbackHost(%q) = true, want false", h)
		}
	}
}

// TestResolveGUITLS_LoopbackPassesThroughUntouched — B_136 (T_060): the ticket's own
// explicit arbitrage. Loopback traffic never leaves the host, so plain HTTP there is
// not a defect this ticket closes, and TLS is not forced on it.
func TestResolveGUITLS_LoopbackPassesThroughUntouched(t *testing.T) {
	dir := t.TempDir()

	enabled, cert, key, autoGen, err := ResolveGUITLS("127.0.0.1", false, "", "", dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enabled || cert != "" || key != "" || autoGen {
		t.Fatalf("loopback host must pass through untouched, got enabled=%v cert=%q key=%q autoGen=%v", enabled, cert, key, autoGen)
	}
	// No cert should have been generated on disk either.
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("expected no files generated for a loopback host, found %v", entries)
	}
}

// TestResolveGUITLS_AlreadyConfiguredWins — an operator-provided certificate on a
// non-loopback host is honoured as-is, no auto-generation.
func TestResolveGUITLS_AlreadyConfiguredWins(t *testing.T) {
	dir := t.TempDir()

	enabled, cert, key, autoGen, err := ResolveGUITLS("0.0.0.0", true, "/etc/etc-collector/real-cert.pem", "/etc/etc-collector/real-key.pem", dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !enabled || cert != "/etc/etc-collector/real-cert.pem" || key != "/etc/etc-collector/real-key.pem" || autoGen {
		t.Fatalf("an already-configured certificate must be honoured untouched, got enabled=%v cert=%q key=%q autoGen=%v", enabled, cert, key, autoGen)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("expected no bootstrap cert generated when one is already configured, found %v", entries)
	}
}

// TestResolveGUITLS_NonLoopbackNoTLSAutoGenerates is the fleet-non-regression case:
// a collector already running on a non-loopback host, with no certificate configured,
// must keep starting after this fix ships — now with TLS instead of plaintext.
func TestResolveGUITLS_NonLoopbackNoTLSAutoGenerates(t *testing.T) {
	dir := t.TempDir()

	enabled, cert, key, autoGen, err := ResolveGUITLS("0.0.0.0", false, "", "", dir, false)
	if err != nil {
		t.Fatalf("a non-loopback host with no TLS configured must NOT refuse to start — it must auto-generate a bootstrap certificate: %v", err)
	}
	if !enabled || cert == "" || key == "" || !autoGen {
		t.Fatalf("expected TLS auto-enabled with a generated cert, got enabled=%v cert=%q key=%q autoGen=%v", enabled, cert, key, autoGen)
	}
	if _, err := os.Stat(cert); err != nil {
		t.Fatalf("generated cert file does not exist: %v", err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Fatalf("generated key file does not exist: %v", err)
	}
}

// TestResolveGUITLS_ExplicitOptOutAllowsPlaintext — the "opt-out explicite" the
// ticket asks for, alongside TLS being required by default.
func TestResolveGUITLS_ExplicitOptOutAllowsPlaintext(t *testing.T) {
	dir := t.TempDir()

	enabled, cert, key, autoGen, err := ResolveGUITLS("0.0.0.0", false, "", "", dir, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enabled || cert != "" || key != "" || autoGen {
		t.Fatalf("an explicit opt-out must leave TLS off and generate nothing, got enabled=%v cert=%q key=%q autoGen=%v", enabled, cert, key, autoGen)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("expected no cert generated under the insecure opt-out, found %v", entries)
	}
}

// TestResolveGUITLS_GenerationFailureIsRefused proves the one genuine "refuse to
// start" case: TLS is required, not opted out of, and a bootstrap certificate could
// not be generated (here: certDir is actually a file, so MkdirAll fails).
func TestResolveGUITLS_GenerationFailureIsRefused(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "tls")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0600); err != nil {
		t.Fatalf("seed blocking file: %v", err)
	}

	_, _, _, _, err := ResolveGUITLS("0.0.0.0", false, "", "", blocker, false)
	if err == nil {
		t.Fatal("expected an error when the bootstrap certificate cannot be generated and there is no opt-out")
	}
}
