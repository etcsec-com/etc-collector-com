package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestServerMode_CanMintAndUseAJWT — B_084 (T_067), proven the way the itest harness
// proves it (docs/testing/tools/itest/scenarios/10-endpoints.sh): build the real
// binary, start `etc-collector server` exactly as an operator would, generate a real
// GUI token via `etc-collector gui-token reset`, and POST /api/v1/auth/token over real
// HTTP. Before this fix, that request returned 500 token_generation_failed on a fresh
// install — cfg.Auth.PrivateKey was nil because nothing ever generated a keypair, only
// tried to load one that didn't exist yet (server.go's old ensureKeys). All 8
// authMiddleware routes were unreachable as a direct consequence.
//
// Also exercises B_092 end-to-end: ETCSEC_CONFIG_DIR points both the token-generating
// process and the server at the same directory — the acceptance criterion is that the
// env var is EFFECTIVE in server mode, which this proves by using nothing else to
// locate config/keys.
func TestServerMode_CanMintAndUseAJWT(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the real binary — skipped in -short")
	}

	binPath := buildCollectorBinary(t)
	configDir := t.TempDir()
	port := freeTCPPort(t)

	env := append(os.Environ(), "ETCSEC_CONFIG_DIR="+configDir)

	// Mirrors the harness's own sequence: generate the GUI token via the real CLI
	// command, not by writing guitoken files directly.
	token := resetGuiTokenViaCLI(t, binPath, env)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "server",
		"--port", fmt.Sprintf("%d", port),
		"--host", "127.0.0.1",
	)
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		if t.Failed() {
			t.Logf("server stdout:\n%s", stdout.String())
			t.Logf("server stderr:\n%s", stderr.String())
		}
	})

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForHealth(t, baseURL)

	// POST /api/v1/auth/token — the exact request B_084's matrix row measured.
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/auth/token", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GUI-Token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/auth/token: %v", err)
	}
	defer resp.Body.Close()

	var body struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expiresAt"`
		Error     string `json:"error"`
		Message   string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/token = %d (%s: %s), want 200 — this is exactly B_084's "+
			"500 token_generation_failed if it regresses", resp.StatusCode, body.Error, body.Message)
	}
	if body.Token == "" {
		t.Fatal("200 response but no token in the body")
	}
	if matched, _ := regexp.MatchString(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`, body.Token); !matched {
		t.Fatalf("token does not look like a JWT (header.payload.signature): %s", body.Token)
	}

	// Prove the 8 authMiddleware routes are actually reachable with this token now —
	// the acceptance criterion's second half, not just that minting succeeds.
	authReq, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/info/capabilities", nil)
	if err != nil {
		t.Fatalf("build auth request: %v", err)
	}
	authReq.Header.Set("Authorization", "Bearer "+body.Token)
	authResp, err := http.DefaultClient.Do(authReq)
	if err != nil {
		t.Fatalf("GET /api/v1/info/capabilities: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/info/capabilities with a freshly minted JWT = %d, want 200 (an authMiddleware route must be reachable)", authResp.StatusCode)
	}
}

var (
	sharedBinOnce sync.Once
	sharedBinPath string
	sharedBinErr  error
)

// buildCollectorBinary compiles the real etc-collector binary once per test binary
// run and shares it across every test in this package that needs it — building it
// per-test would otherwise double the wall-clock cost of this file's two tests for no
// benefit, since neither mutates the compiled binary.
func buildCollectorBinary(t *testing.T) string {
	t.Helper()
	sharedBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "etc-collector-itest-bin")
		if err != nil {
			sharedBinErr = err
			return
		}
		binPath := filepath.Join(dir, "etc-collector")
		cmd := exec.Command("go", "build", "-o", binPath, ".")
		out, buildErr := cmd.CombinedOutput()
		if buildErr != nil {
			sharedBinErr = fmt.Errorf("go build ./cmd/etc-collector: %w\n%s", buildErr, out)
			return
		}
		sharedBinPath = binPath
	})
	if sharedBinErr != nil {
		t.Fatalf("%v", sharedBinErr)
	}
	return sharedBinPath
}

// resetGuiTokenViaCLI runs `etc-collector gui-token reset` and extracts the plaintext
// token from its stdout — the exact string the operator (or, in the harness, a grep
// for etcsec_gt_) reads.
func resetGuiTokenViaCLI(t *testing.T, binPath string, env []string) string {
	t.Helper()
	cmd := exec.Command(binPath, "gui-token", "reset")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gui-token reset: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`etcsec_gt_[0-9a-f]+`).FindString(string(out))
	if m == "" {
		t.Fatalf("no token found in gui-token reset output:\n%s", out)
	}
	return m
}

// freeTCPPort asks the OS for an unused port and immediately releases it. A small
// TOCTOU risk (another process could grab it before the server binds), acceptable for
// a local test.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// waitForHealth polls /health until it responds 200 or the deadline passes.
func waitForHealth(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s/health never became reachable", baseURL)
}

// TestServerMode_ConfigDirFlagWinsOverEnvVar — B_092 (T_067). The acceptance
// criterion is explicit that only one of --config-dir / ETCSEC_CONFIG_DIR may win
// when both are set, and the delivery must say which. This proves --config-dir does,
// end to end: two directories with DIFFERENT auth.tokenLifetime values in their
// config.yaml, --config-dir pointed at one and ETCSEC_CONFIG_DIR at the other, and
// /api/v1/admin/config must echo the --config-dir directory's value.
func TestServerMode_ConfigDirFlagWinsOverEnvVar(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the real binary — skipped in -short")
	}

	binPath := buildCollectorBinary(t)
	flagDir := t.TempDir()
	envDir := t.TempDir()
	port := freeTCPPort(t)

	const flagDirLifetime = "999h"
	const envDirLifetime = "111h"
	// /admin/config echoes time.Duration.String()'s canonical form, not the input
	// literal — "999h" comes back as "999h0m0s".
	const flagDirLifetimeEchoed = "999h0m0s"
	writeMinimalConfigYAML(t, flagDir, flagDirLifetime)
	writeMinimalConfigYAML(t, envDir, envDirLifetime)

	// The GUI token must come from the SAME directory the server will actually use
	// (flagDir, if the flag correctly wins) — generated with its own env, entirely
	// separate from the server process's env below.
	token := resetGuiTokenViaCLI(t, binPath, append(os.Environ(), "ETCSEC_CONFIG_DIR="+flagDir))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "server",
		"--port", fmt.Sprintf("%d", port),
		"--host", "127.0.0.1",
		"--config-dir", flagDir,
	)
	// ETCSEC_CONFIG_DIR set to a DIFFERENT directory than --config-dir — if the env
	// var won, or if both were merged, admin/config would echo envDirLifetime instead.
	cmd.Env = append(os.Environ(), "ETCSEC_CONFIG_DIR="+envDir)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		if t.Failed() {
			t.Logf("server stdout:\n%s", stdout.String())
			t.Logf("server stderr:\n%s", stderr.String())
		}
	})

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForHealth(t, baseURL)

	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/admin/config", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-GUI-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/admin/config: %v", err)
	}
	defer resp.Body.Close()

	var body struct {
		Auth struct {
			TokenLifetime string `json:"tokenLifetime"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response (status %d): %v", resp.StatusCode, err)
	}

	if body.Auth.TokenLifetime != flagDirLifetimeEchoed {
		t.Fatalf("auth.tokenLifetime = %q, want %q (--config-dir's value, echoed) — anything else (e.g. envDir's %q) means ETCSEC_CONFIG_DIR won instead",
			body.Auth.TokenLifetime, flagDirLifetimeEchoed, envDirLifetime)
	}
}

// writeMinimalConfigYAML writes a config.yaml under dir carrying a distinctive
// auth.tokenLifetime, so a test can tell which directory's file a running server
// actually loaded.
func writeMinimalConfigYAML(t *testing.T, dir, tokenLifetime string) {
	t.Helper()
	content := fmt.Sprintf("auth:\n  tokenLifetime: %s\n", tokenLifetime)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0600); err != nil {
		t.Fatalf("write config.yaml in %s: %v", dir, err)
	}
}
