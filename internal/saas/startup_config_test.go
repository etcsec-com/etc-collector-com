package saas

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/providers/azure"
)

// TestResolveAuthTokenLifetime — B_047 (T_048). The daemon's embedded GUI startup path
// (StartEmbeddedGUI) used to always ship config.Default()'s hardcoded 30 days,
// regardless of what the customer's config.yaml said. This is the pure function that
// closes it, tested directly (StartEmbeddedGUI itself starts a real HTTP server and
// isn't a unit-test target).
func TestResolveAuthTokenLifetime(t *testing.T) {
	const fallback = 30 * 24 * time.Hour

	t.Run("config.yaml value wins over the fallback", func(t *testing.T) {
		dir := t.TempDir()
		writeConfigYAML(t, dir, "auth:\n  tokenLifetime: 720h\n")

		got, err := resolveAuthTokenLifetime(dir, fallback)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 720*time.Hour {
			t.Fatalf("got %v, want 720h", got)
		}
	})

	t.Run("no config.yaml falls back cleanly", func(t *testing.T) {
		dir := t.TempDir() // empty — no config.yaml written

		// A missing file DOES surface as an error here (unlike config.Load with a
		// search path, an explicit path that doesn't exist isn't a tolerated
		// viper.ConfigFileNotFoundError) — the contract, exercised by the caller in
		// StartEmbeddedGUI, is that the error is logged and the fallback is still used.
		got, err := resolveAuthTokenLifetime(dir, fallback)
		if err == nil {
			t.Fatal("expected an error for a missing config.yaml (the caller logs it and keeps the fallback)")
		}
		if got != fallback {
			t.Fatalf("got %v, want the fallback %v even when the file is missing", got, fallback)
		}
	})

	t.Run("config.yaml present but omitting auth.tokenLifetime falls back", func(t *testing.T) {
		dir := t.TempDir()
		writeConfigYAML(t, dir, "log:\n  level: debug\n")

		got, err := resolveAuthTokenLifetime(dir, fallback)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != fallback {
			t.Fatalf("got %v, want the fallback %v — an omitted key must never resolve to 0", got, fallback)
		}
	})
}

func writeConfigYAML(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
}

// TestBuildAzureConfig — B_026 (T_048). The daemon's Azure provider used to be built
// with ClientSecret only; a local certificate override must layer on top of the
// SaaS-managed tenantId/clientId without a cloud-pushed field ever being involved.
func TestBuildAzureConfig(t *testing.T) {
	saasCfg := &SaaSAzureConfig{
		TenantID:     "tenant-1",
		ClientID:     "client-1",
		ClientSecret: "cloud-managed-secret",
	}

	t.Run("no override — client secret used exactly as before (non-regression)", func(t *testing.T) {
		got := buildAzureConfig(saasCfg, nil)
		if got.TenantID != "tenant-1" || got.ClientID != "client-1" {
			t.Fatalf("tenantId/clientId not carried through: %+v", got)
		}
		if got.ClientSecret != "cloud-managed-secret" {
			t.Fatalf("client secret not carried through: %+v", got)
		}
		if got.HasCertificate() {
			t.Fatal("no certificate override was given — HasCertificate must be false")
		}
		if !got.HasCredential() {
			t.Fatal("the cloud-managed secret must count as a usable credential")
		}
	})

	t.Run("local certificate override applied, tenantId/clientId still cloud-managed", func(t *testing.T) {
		overrides := &AzureOverrides{
			ClientCertPath:     "/etc/etc-collector/entra-app.pfx",
			ClientCertPassword: "cert-password",
		}
		got := buildAzureConfig(saasCfg, overrides)

		if got.TenantID != "tenant-1" || got.ClientID != "client-1" {
			t.Fatalf("tenantId/clientId must still come from the SaaS-managed config: %+v", got)
		}
		if got.ClientCertPath != overrides.ClientCertPath || got.ClientCertPassword != overrides.ClientCertPassword {
			t.Fatalf("certificate override not applied: %+v", got)
		}
		if !got.HasCertificate() {
			t.Fatal("expected HasCertificate() to report true once the override is applied")
		}
		// The cloud-managed secret is still present in the built config — newCredential
		// (internal/providers/azure/credential.go) is what actually prefers the
		// certificate, and that precedence is exercised by its own test suite (T_026).
		// This test only proves the merge, not azidentity's internal precedence.
		if got.ClientSecret != "cloud-managed-secret" {
			t.Fatalf("expected the cloud secret to remain present (unused, not dropped): %+v", got)
		}
	})

	t.Run("no SaaS config yet — override alone still produces a usable credential shape", func(t *testing.T) {
		overrides := &AzureOverrides{ClientCertPath: "/path/to/cert.pfx"}
		got := buildAzureConfig(nil, overrides)
		if got.TenantID != "" || got.ClientID != "" {
			t.Fatalf("expected empty tenantId/clientId with a nil SaaS config: %+v", got)
		}
		if !got.HasCertificate() {
			t.Fatal("expected the certificate override to still apply")
		}
	})

	t.Run("nil saasConfig and nil overrides — safe zero value", func(t *testing.T) {
		got := buildAzureConfig(nil, nil)
		if got.HasCredential() {
			t.Fatalf("expected no usable credential from a fully empty config: %+v", got)
		}
	})
}

// TestAzureOverrides_PreferredOverClientSecretByNewClient proves the wiring at the
// azure.Config boundary: once buildAzureConfig applies a certificate override,
// azure.NewClient reports the shape newCredential (T_026) will treat as
// certificate-preferred — a live connect isn't exercised here (no network in a unit
// test), only that construction succeeds and reports the right credential kind.
func TestAzureOverrides_PreferredOverClientSecretByNewClient(t *testing.T) {
	saasCfg := &SaaSAzureConfig{TenantID: "t1", ClientID: "c1", ClientSecret: "secret"}
	overrides := &AzureOverrides{ClientCertPath: "/etc/etc-collector/entra-app.pem"}

	cfg := buildAzureConfig(saasCfg, overrides)
	client, err := azure.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient must accept a cert-and-secret config without dialing anything: %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil client")
	}
	if !cfg.HasCertificate() {
		t.Fatal("expected the built config to report a certificate")
	}
}
