package trial

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/providers/azure"
)

// TestAzureConfig_CertificateFieldsRoundTrip checks that the certificate
// configuration survives the trip from each entry point to azure.Config.
//
// Two of the three entry points live here (config.yaml through the real viper
// loader, and the SaaS/trial command params). The third, the audit CLI flags,
// is covered by TestAzureConfig_CertificateFieldsRoundTrip_CLIFlags in
// cmd/etc-collector — cobra flags bind to package main variables, which no
// other package can reach.
func TestAzureConfig_CertificateFieldsRoundTrip(t *testing.T) {
	t.Run("config.yaml reaches config.AzureConfig", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "collector.yaml")
		yaml := `
server:
  port: 8080
api:
  port: 8081
azure:
  tenantId: tenant-uuid
  clientId: client-uuid
  clientCertPath: /etc/etc-collector/entra.pem
  clientCertPassword: hunter2
`
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		if got := cfg.Azure.ClientCertPath; got != "/etc/etc-collector/entra.pem" {
			t.Errorf("clientCertPath = %q", got)
		}
		if got := cfg.Azure.ClientCertPassword; got != "hunter2" {
			t.Errorf("clientCertPassword = %q", got)
		}

		// The fields exist so an operator can configure certificate auth in
		// collector.yaml — but see the delivery: no audit path reads
		// config.Azure today (clientSecret included), it is consumed only by
		// the admin API. Mapping to the provider config is the last hop.
		provider := azure.Config{
			TenantID:           cfg.Azure.TenantID,
			ClientID:           cfg.Azure.ClientID,
			ClientSecret:       cfg.Azure.ClientSecret,
			ClientCertPath:     cfg.Azure.ClientCertPath,
			ClientCertPEM:      cfg.Azure.ClientCertPEM,
			ClientCertPassword: cfg.Azure.ClientCertPassword,
		}
		if !provider.HasCertificate() || provider.ClientSecret != "" {
			t.Fatalf("expected a certificate-only provider config, got %+v", provider)
		}
	})

	t.Run("SaaS command params: certificate path", func(t *testing.T) {
		cfg, err := parseAzureConfig(map[string]interface{}{
			"azure": map[string]interface{}{
				"tenantId":           "tenant-uuid",
				"clientId":           "client-uuid",
				"clientCertificate":  "/var/lib/etc-collector/entra.pfx",
				"clientCertPassword": "hunter2",
			},
		})
		if err != nil {
			t.Fatalf("parseAzureConfig: %v", err)
		}
		if cfg.ClientCertPath != "/var/lib/etc-collector/entra.pfx" {
			t.Errorf("ClientCertPath = %q", cfg.ClientCertPath)
		}
		if cfg.ClientCertPEM != "" {
			t.Errorf("a path must not be stored as inline PEM: %q", cfg.ClientCertPEM)
		}
		if cfg.ClientCertPassword != "hunter2" {
			t.Errorf("ClientCertPassword = %q", cfg.ClientCertPassword)
		}
	})

	t.Run("SaaS command params: inline PEM", func(t *testing.T) {
		const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
		cfg, err := parseAzureConfig(map[string]interface{}{
			"azure": map[string]interface{}{
				"tenantId":          "tenant-uuid",
				"clientId":          "client-uuid",
				"clientCertificate": pem,
			},
		})
		if err != nil {
			t.Fatalf("parseAzureConfig: %v", err)
		}
		if cfg.ClientCertPEM != pem {
			t.Errorf("PEM content must be carried inline, got %q", cfg.ClientCertPEM)
		}
		if cfg.ClientCertPath != "" {
			t.Errorf("inline PEM must not be treated as a path: %q", cfg.ClientCertPath)
		}
	})

	t.Run("SaaS command params: secret still accepted", func(t *testing.T) {
		cfg, err := parseAzureConfig(map[string]interface{}{
			"azure": map[string]interface{}{
				"tenantId":     "tenant-uuid",
				"clientId":     "client-uuid",
				"clientSecret": "s3cr3t",
			},
		})
		if err != nil {
			t.Fatalf("existing secret-based commands must keep working: %v", err)
		}
		if cfg.ClientSecret != "s3cr3t" || cfg.HasCertificate() {
			t.Fatalf("expected a secret-only config, got %+v", cfg)
		}
	})

	t.Run("SaaS command params: neither credential is rejected", func(t *testing.T) {
		_, err := parseAzureConfig(map[string]interface{}{
			"azure": map[string]interface{}{
				"tenantId": "tenant-uuid",
				"clientId": "client-uuid",
			},
		})
		if err == nil {
			t.Fatal("expected an error when neither a secret nor a certificate is provided")
		}
	})

	t.Run("SaaS command params: tenant and client are still mandatory", func(t *testing.T) {
		if _, err := parseAzureConfig(map[string]interface{}{
			"azure": map[string]interface{}{"clientSecret": "s3cr3t"},
		}); err == nil {
			t.Fatal("expected an error when tenantId/clientId are missing")
		}
	})
}
