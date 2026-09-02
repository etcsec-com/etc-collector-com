package main

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/providers/azure"
)

// TestAzureConfig_CertificateFieldsRoundTrip_CLIFlags is the CLI half of the
// round-trip check (the other two entry points are covered by
// TestAzureConfig_CertificateFieldsRoundTrip in internal/trial): the audit
// command's flags must reach azure.Config, and --client-secret must have
// stopped being mandatory so a certificate alone is a valid invocation.
func TestAzureConfig_CertificateFieldsRoundTrip_CLIFlags(t *testing.T) {
	flags := auditAzureCmd.Flags()

	for _, name := range []string{"client-cert", "client-cert-password"} {
		if flags.Lookup(name) == nil {
			t.Fatalf("audit azure is missing the --%s flag", name)
		}
	}

	t.Run("certificate flags reach azure.Config", func(t *testing.T) {
		defer resetAzureFlagVars()
		if err := flags.Parse([]string{
			"--tenant-id", "tenant-uuid",
			"--client-id", "client-uuid",
			"--client-cert", "/etc/etc-collector/entra.pem",
			"--client-cert-password", "hunter2",
		}); err != nil {
			t.Fatalf("parse flags: %v", err)
		}

		cfg := azureConfigFromFlags()
		if cfg.ClientCertPath != "/etc/etc-collector/entra.pem" {
			t.Errorf("ClientCertPath = %q", cfg.ClientCertPath)
		}
		if cfg.ClientCertPassword != "hunter2" {
			t.Errorf("ClientCertPassword = %q", cfg.ClientCertPassword)
		}
		if !cfg.HasCredential() {
			t.Error("a certificate alone must satisfy the credential requirement")
		}
		if got := azureAuthMethodLabel(); got != "certificate" {
			t.Errorf("auth label = %q, want certificate", got)
		}
	})

	t.Run("secret flags still reach azure.Config unchanged", func(t *testing.T) {
		defer resetAzureFlagVars()
		if err := flags.Parse([]string{
			"--tenant-id", "tenant-uuid",
			"--client-id", "client-uuid",
			"--client-secret", "s3cr3t",
		}); err != nil {
			t.Fatalf("parse flags: %v", err)
		}

		cfg := azureConfigFromFlags()
		if cfg.ClientSecret != "s3cr3t" {
			t.Errorf("ClientSecret = %q", cfg.ClientSecret)
		}
		if cfg.HasCertificate() {
			t.Error("no certificate was passed")
		}
		if got := azureAuthMethodLabel(); got != "client-secret" {
			t.Errorf("auth label = %q, want client-secret", got)
		}
	})

	// Updated by T_038. --tenant-id and --client-id used to be asserted as
	// cobra-required here; they no longer are, and that reversal is the point.
	// cobra rejects a missing required flag BEFORE RunE, i.e. before config.yaml or
	// AZURE_* is ever consulted — which would have made the whole azure: wiring
	// unreachable. The obligation moved rather than disappeared: it is now enforced
	// after resolution by azure.NewClient.
	t.Run("credential flags are enforced after resolution, not by cobra", func(t *testing.T) {
		const requiredAnnotation = "cobra_annotation_bash_completion_one_required_flag"

		for _, name := range []string{"tenant-id", "client-id", "client-secret"} {
			if ann := flags.Lookup(name).Annotations; ann != nil {
				if _, required := ann[requiredAnnotation]; required {
					t.Errorf("--%s must not be cobra-required: it would short-circuit the "+
						"config.yaml / AZURE_* resolution before RunE runs", name)
				}
			}
		}

		// …and the requirement is still real.
		defer resetAzureFlagVars()
		if _, err := azure.NewClient(azure.Config{ClientID: "c", ClientSecret: "s"}); err == nil {
			t.Error("a missing tenant ID must still be rejected, after resolution")
		}
		if _, err := azure.NewClient(azure.Config{TenantID: "t", ClientSecret: "s"}); err == nil {
			t.Error("a missing client ID must still be rejected, after resolution")
		}
	})
}

// TestAzureConfig_PrecedenceOverConfigFile — B_033 (T_038). The azure: section was
// parsed, echoed back by the admin API, and never used to run an audit. This asserts
// both halves: the file is now read, and a CLI flag still wins over it — the latter is
// the non-regression guarantee, since every existing deployment configures by flag.
func TestAzureConfig_PrecedenceOverConfigFile(t *testing.T) {
	fileCfg := &config.Config{Azure: config.AzureConfig{
		TenantID:           "tenant-from-file",
		ClientID:           "client-from-file",
		ClientSecret:       "secret-from-file",
		ClientCertPath:     "/etc/etc-collector/from-file.pem",
		ClientCertPEM:      "-----BEGIN CERTIFICATE-----from-file",
		ClientCertPassword: "password-from-file",
	}}

	// cfg is the package-level config of cmd/etc-collector; no file on disk needed.
	withFileConfig := func(t *testing.T, c *config.Config) {
		t.Helper()
		orig := cfg
		cfg = c
		t.Cleanup(func() { cfg = orig })
	}

	t.Run("config.yaml alone is now actually used", func(t *testing.T) {
		defer resetAzureFlagVars()
		withFileConfig(t, fileCfg)

		got := azureConfigFromFlags()
		if got.TenantID != "tenant-from-file" || got.ClientID != "client-from-file" {
			t.Fatalf("azure: section still ignored: tenant=%q client=%q", got.TenantID, got.ClientID)
		}
		if got.ClientSecret != "secret-from-file" {
			t.Errorf("ClientSecret = %q, want the file value", got.ClientSecret)
		}
		if got.ClientCertPath != "/etc/etc-collector/from-file.pem" {
			t.Errorf("ClientCertPath = %q, want the file value", got.ClientCertPath)
		}
		if got.ClientCertPEM != "-----BEGIN CERTIFICATE-----from-file" {
			t.Errorf("ClientCertPEM = %q — the inline PEM has no flag, the file is its only local source", got.ClientCertPEM)
		}
		if got.ClientCertPassword != "password-from-file" {
			t.Errorf("ClientCertPassword = %q, want the file value", got.ClientCertPassword)
		}
	})

	// THE non-regression test: an existing deployment passes flags and must obtain
	// exactly the same azure.Config as before this change.
	t.Run("CLI flag beats config.yaml", func(t *testing.T) {
		defer resetAzureFlagVars()
		withFileConfig(t, fileCfg)

		if err := auditAzureCmd.Flags().Parse([]string{
			"--tenant-id", "tenant-from-flag",
			"--client-id", "client-from-flag",
			"--client-secret", "secret-from-flag",
			"--client-cert", "/tmp/from-flag.pem",
			"--client-cert-password", "password-from-flag",
		}); err != nil {
			t.Fatalf("parse flags: %v", err)
		}

		got := azureConfigFromFlags()
		for _, tc := range []struct{ field, got, want string }{
			{"TenantID", got.TenantID, "tenant-from-flag"},
			{"ClientID", got.ClientID, "client-from-flag"},
			{"ClientSecret", got.ClientSecret, "secret-from-flag"},
			{"ClientCertPath", got.ClientCertPath, "/tmp/from-flag.pem"},
			{"ClientCertPassword", got.ClientCertPassword, "password-from-flag"},
		} {
			if tc.got != tc.want {
				t.Errorf("%s = %q, want %q — the flag must win, existing deployments depend on it", tc.field, tc.got, tc.want)
			}
		}
	})

	t.Run("environment sits between flag and file", func(t *testing.T) {
		defer resetAzureFlagVars()
		withFileConfig(t, fileCfg)
		t.Setenv("AZURE_TENANT_ID", "tenant-from-env")
		t.Setenv("AZURE_CLIENT_SECRET", "secret-from-env")

		// env alone beats the file
		if got := azureConfigFromFlags(); got.TenantID != "tenant-from-env" {
			t.Errorf("TenantID = %q, want the env value to beat the file", got.TenantID)
		}

		// flag beats env
		if err := auditAzureCmd.Flags().Parse([]string{"--tenant-id", "tenant-from-flag"}); err != nil {
			t.Fatalf("parse flags: %v", err)
		}
		if got := azureConfigFromFlags(); got.TenantID != "tenant-from-flag" {
			t.Errorf("TenantID = %q, want the flag to beat the env", got.TenantID)
		}
	})

	t.Run("no source at all is still rejected", func(t *testing.T) {
		defer resetAzureFlagVars()
		withFileConfig(t, &config.Config{})

		_, err := azure.NewClient(azureConfigFromFlags())
		if err == nil {
			t.Fatal("an unconfigured audit must fail, not run with empty credentials")
		}
	})

	t.Run("a nil config is not a panic", func(t *testing.T) {
		defer resetAzureFlagVars()
		withFileConfig(t, nil)

		if got := azureConfigFromFlags(); got.TenantID != "" {
			t.Errorf("TenantID = %q, want empty when no config is loaded", got.TenantID)
		}
	})
}

func resetAzureFlagVars() {
	auditAzureTenantID = ""
	auditAzureClientID = ""
	auditAzureClientSecret = ""
	auditAzureClientCert = ""
	auditAzureClientCertPass = ""
}
