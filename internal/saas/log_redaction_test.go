package saas

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/guitoken"
	"github.com/etcsec-com/etc-collector/internal/logger"
)

func TestIsSecretFieldName(t *testing.T) {
	secret := []string{"ApiKey", "BindPassword", "ClientSecret", "ClientCertPassword", "Token", "WebhookSecret", "apikey"}
	notSecret := []string{"ClientCertPath", "TenantID", "ClientID", "URL", "BaseDN", "TokenLifetime", "TLSCACertPEM", "CollectorID"}

	for _, name := range secret {
		if !isSecretFieldName(name) {
			t.Errorf("isSecretFieldName(%q) = false, want true", name)
		}
	}
	for _, name := range notSecret {
		if isSecretFieldName(name) {
			t.Errorf("isSecretFieldName(%q) = true, want false", name)
		}
	}
}

// TestCollectSecretStrings_KnownFields — non-regression: the fields GET_LOGS
// redaction is actually protecting today (B_135, T_060).
func TestCollectSecretStrings_KnownFields(t *testing.T) {
	creds := &Credentials{
		CollectorID: "collector-1", // not a secret — must NOT be collected
		ApiKey:      "saas-api-key-value",
		Config: CollectorConfig{
			LDAP:  &SaaSLDAPConfig{URL: "ldaps://dc01:636", BindPassword: "ldap-bind-password-value"},
			Azure: &SaaSAzureConfig{TenantID: "t1", ClientSecret: "azure-client-secret-value"},
		},
	}

	var got []string
	collectSecretStrings(reflect.ValueOf(creds), &got)

	want := map[string]bool{
		"saas-api-key-value":        false,
		"ldap-bind-password-value":  false,
		"azure-client-secret-value": false,
	}
	for _, s := range got {
		if _, ok := want[s]; ok {
			want[s] = true
		}
		if s == "collector-1" || s == "ldaps://dc01:636" || s == "t1" {
			t.Errorf("collected a non-secret field value: %q", s)
		}
	}
	for s, found := range want {
		if !found {
			t.Errorf("expected %q among collected secrets, got %v", s, got)
		}
	}
}

// TestCollectSecretStrings_GeneralizesToANewSecretField — the acceptance criterion,
// tested directly: "un nouveau secret ajouté au code est couvert sans modifier une
// liste de motifs." A struct type defined ONLY in this test, unknown to
// collectSecretStrings, still gets its secret-named field redacted — proving the
// mechanism generalizes by naming convention, not by an enumerated list this test
// would otherwise have to extend.
func TestCollectSecretStrings_GeneralizesToANewSecretField(t *testing.T) {
	type FutureIntegrationConfig struct {
		Endpoint      string // not a secret
		WebhookSecret string // a brand new secret field, never seen by log_redaction.go
	}
	cfg := FutureIntegrationConfig{
		Endpoint:      "https://hooks.example.com/callback",
		WebhookSecret: "brand-new-secret-nobody-taught-the-redactor-about",
	}

	var got []string
	collectSecretStrings(reflect.ValueOf(cfg), &got)

	found := false
	for _, s := range got {
		if s == cfg.WebhookSecret {
			found = true
		}
		if s == cfg.Endpoint {
			t.Fatalf("collected a non-secret field: %q", s)
		}
	}
	if !found {
		t.Fatalf("a new field merely named ...Secret was not collected — the mechanism isn't actually structural: got %v", got)
	}
}

// TestCollectSecretStrings_NestedAndNil proves the recursive walk handles pointers,
// nested structs, and nil safely — the shapes Credentials/LDAPOverrides/AzureOverrides
// actually have.
func TestCollectSecretStrings_NestedAndNil(t *testing.T) {
	t.Run("nil pointer is safe", func(t *testing.T) {
		var overrides *AzureOverrides
		var got []string
		collectSecretStrings(reflect.ValueOf(overrides), &got)
		if len(got) != 0 {
			t.Fatalf("expected nothing from a nil pointer, got %v", got)
		}
	})

	t.Run("nested pointer field is walked", func(t *testing.T) {
		creds := &Credentials{
			Config: CollectorConfig{
				Azure: &SaaSAzureConfig{ClientSecret: "nested-secret"},
			},
		}
		var got []string
		collectSecretStrings(reflect.ValueOf(creds), &got)
		if !contains(got, "nested-secret") {
			t.Fatalf("expected the nested Azure.ClientSecret to be collected, got %v", got)
		}
	})

	t.Run("empty secret field contributes nothing", func(t *testing.T) {
		creds := &Credentials{ApiKey: ""}
		var got []string
		collectSecretStrings(reflect.ValueOf(creds), &got)
		if len(got) != 0 {
			t.Fatalf("expected no values from empty fields, got %v", got)
		}
	})
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestRedactKnownSecrets(t *testing.T) {
	token, err := guitoken.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	text := "line one\n" +
		"apiKey used to connect: my-api-key-value\n" +
		"a stray token appeared: " + token + "\n" +
		"line four, nothing sensitive"

	got := redactKnownSecrets(text, []string{"my-api-key-value"})

	if strings.Contains(got, "my-api-key-value") {
		t.Fatalf("known secret value survived redaction: %s", got)
	}
	if strings.Contains(got, token) {
		t.Fatalf("token survived format-based redaction: %s", got)
	}
	if !strings.Contains(got, "line one") || !strings.Contains(got, "line four, nothing sensitive") {
		t.Fatalf("redaction removed unrelated text: %s", got)
	}
}

// TestDaemon_KnownSecretValues_RedactsRealLogFile — end-to-end through the real
// Daemon.knownSecretValues and readLastNLines (the exact two calls executeGetLogs
// makes), proving the wiring closes B_135, not just the pure helpers in isolation.
func TestDaemon_KnownSecretValues_RedactsRealLogFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "collector.log")

	const apiKey = "T060-REAL-SAAS-API-KEY"
	const bindPassword = "T060-REAL-LDAP-BIND-PASSWORD"
	const certPassword = "T060-REAL-CERT-PASSWORD"

	d := &Daemon{
		logger: logger.NewNop(),
		creds: &Credentials{
			ApiKey: apiKey,
			Config: CollectorConfig{
				LDAP: &SaaSLDAPConfig{BindPassword: bindPassword},
			},
		},
		AzureOverrides: &AzureOverrides{ClientCertPassword: certPassword},
		logFilePath:    logPath,
	}

	logLine := "some log line accidentally contains " + apiKey + " and " + bindPassword + " and " + certPassword + "\n"
	if err := os.WriteFile(logPath, []byte(logLine), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	content, err := readLastNLines(d.logFilePath, 100)
	if err != nil {
		t.Fatalf("readLastNLines: %v", err)
	}
	redacted := redactKnownSecrets(content, d.knownSecretValues())

	for _, secret := range []string{apiKey, bindPassword, certPassword} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("secret %q survived redaction: %s", secret, redacted)
		}
	}
	if !strings.Contains(redacted, "[REDACTED:credential]") {
		t.Fatalf("expected redaction markers in output: %s", redacted)
	}
}
