package main

import (
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/spf13/pflag"
)

// TestAuditDiscoverLDAPFlags_NotCobraRequired — T_111. Exact mirror of
// audit_azurecert_test.go's "credential flags are enforced after resolution,
// not by cobra" for the Azure flags: --ldap-url/--ldap-bind-dn/
// --ldap-bind-password/--ldap-base-dn used to be MarkFlagRequired on both
// auditADCmd and discoverADCmd, which made cobra reject the command BEFORE
// RunE ever ran — before LDAP_*/config.yaml were ever consulted. That's what
// broke the README Quick Start Docker's first copyable example for a user who
// followed environment-variables.md's documented LDAP_URL/etc instead of the
// --ldap-* flags.
func TestAuditDiscoverLDAPFlags_NotCobraRequired(t *testing.T) {
	const requiredAnnotation = "cobra_annotation_bash_completion_one_required_flag"
	ldapFieldFlags := []string{"ldap-url", "ldap-bind-dn", "ldap-bind-password", "ldap-base-dn"}

	checkNotRequired := func(t *testing.T, cmdName string, flags *pflag.FlagSet) {
		for _, name := range ldapFieldFlags {
			f := flags.Lookup(name)
			if f == nil {
				t.Fatalf("%s is missing the --%s flag", cmdName, name)
			}
			if ann := f.Annotations; ann != nil {
				if _, required := ann[requiredAnnotation]; required {
					t.Errorf("%s --%s must not be cobra-required: it would short-circuit the "+
						"LDAP_*/config.yaml resolution before RunE runs", cmdName, name)
				}
			}
		}
	}

	t.Run("audit ad", func(t *testing.T) {
		checkNotRequired(t, "audit ad", auditADCmd.Flags())
	})

	t.Run("discover ad", func(t *testing.T) {
		checkNotRequired(t, "discover ad", discoverADCmd.Flags())
	})
}

// TestResolveLDAPConnFromSources_Precedence — T_111. CLI flag > LDAP_*
// environment variable > ldap: in config.yaml, the same precedence
// server.go/daemon already apply via viper — verified here field by field
// since audit.go/discover.go apply it manually via firstNonEmpty.
func TestResolveLDAPConnFromSources_Precedence(t *testing.T) {
	t.Run("env var alone resolves when no flag is set", func(t *testing.T) {
		t.Setenv("LDAP_URL", "ldaps://from-env:636")
		t.Setenv("LDAP_BIND_DN", "CN=env,DC=example,DC=com")
		t.Setenv("LDAP_BIND_PASSWORD", "env-secret")
		t.Setenv("LDAP_BASE_DN", "DC=example,DC=com")

		conn := resolveLDAPConnFromSources("", "", "", "")
		if conn.URL != "ldaps://from-env:636" {
			t.Errorf("URL = %q, want the LDAP_URL value", conn.URL)
		}
		if conn.BindDN != "CN=env,DC=example,DC=com" {
			t.Errorf("BindDN = %q, want the LDAP_BIND_DN value", conn.BindDN)
		}
		if conn.BindPassword != "env-secret" {
			t.Errorf("BindPassword = %q, want the LDAP_BIND_PASSWORD value", conn.BindPassword)
		}
		if conn.BaseDN != "DC=example,DC=com" {
			t.Errorf("BaseDN = %q, want the LDAP_BASE_DN value", conn.BaseDN)
		}
	})

	t.Run("flag wins over env var", func(t *testing.T) {
		t.Setenv("LDAP_URL", "ldaps://from-env:636")
		conn := resolveLDAPConnFromSources("ldaps://from-flag:636", "", "", "")
		if conn.URL != "ldaps://from-flag:636" {
			t.Errorf("URL = %q, want the flag value to win over LDAP_URL", conn.URL)
		}
	})

	t.Run("config.yaml is the last resort, below the env var", func(t *testing.T) {
		prev := cfg
		defer func() { cfg = prev }()
		cfg = config.Default()
		cfg.LDAP.URL = "ldaps://from-config:636"

		t.Run("used when neither flag nor env is set", func(t *testing.T) {
			conn := resolveLDAPConnFromSources("", "", "", "")
			if conn.URL != "ldaps://from-config:636" {
				t.Errorf("URL = %q, want the config.yaml value", conn.URL)
			}
		})

		t.Run("env var still wins over config.yaml", func(t *testing.T) {
			t.Setenv("LDAP_URL", "ldaps://from-env:636")
			conn := resolveLDAPConnFromSources("", "", "", "")
			if conn.URL != "ldaps://from-env:636" {
				t.Errorf("URL = %q, want LDAP_URL to win over config.yaml", conn.URL)
			}
		})
	})
}

// TestRequireLDAPConn — T_111. Replaces the cobra "required flag(s) ... not
// set" error this command used to produce before RunE — the same requirement
// (a real connection needs all 4 fields), enforced after resolution instead.
func TestRequireLDAPConn(t *testing.T) {
	t.Run("all fields present: no error", func(t *testing.T) {
		err := requireLDAPConn(resolvedLDAPConn{
			URL: "ldaps://dc:636", BindDN: "CN=svc,DC=example,DC=com",
			BindPassword: "secret", BaseDN: "DC=example,DC=com",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nothing resolved: names every missing source, flag and env alike", func(t *testing.T) {
		err := requireLDAPConn(resolvedLDAPConn{})
		if err == nil {
			t.Fatal("expected an error when no LDAP connection info resolved from any source")
		}
		for _, want := range []string{"--ldap-url", "LDAP_URL", "--ldap-bind-dn", "LDAP_BIND_DN",
			"--ldap-bind-password", "LDAP_BIND_PASSWORD", "--ldap-base-dn", "LDAP_BASE_DN"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err.Error(), want)
			}
		}
	})
}
