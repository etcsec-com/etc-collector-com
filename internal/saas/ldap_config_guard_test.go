package saas

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/logger"
)

func testDaemon(overrides *LDAPOverrides) *Daemon {
	return &Daemon{
		logger:        logger.NewNop(),
		LDAPOverrides: overrides,
	}
}

func boolPtr(b bool) *bool { return &b }

// TestDaemonEnablesIPAnonymisation — A_004 K5 (RGPD). AnonymizeSignInIPs was reachable
// only through the CLI's --azure-anonymize-ip flag: zero occurrences of AzureAnonymizeIP
// existed in internal/saas, so in daemon mode employee sign-in IPs left the customer
// network in the clear. Both SaaS audit paths now build their RunOptions through
// newRunOptions, which turns it on.
func TestDaemonEnablesIPAnonymisation(t *testing.T) {
	d := testDaemon(nil)

	t.Run("on by default in daemon mode", func(t *testing.T) {
		if opts := d.newRunOptions(nil, true, 0, 0); !opts.AzureAnonymizeIP {
			t.Fatal("AzureAnonymizeIP must default to true in daemon mode")
		}
		if opts := d.newRunOptions(map[string]interface{}{"includeDetails": true}, true, 0, 0); !opts.AzureAnonymizeIP {
			t.Fatal("unrelated parameters must not disable AzureAnonymizeIP")
		}
	})

	t.Run("explicit cloud opt-out honoured", func(t *testing.T) {
		opts := d.newRunOptions(map[string]interface{}{"azureAnonymizeIp": false}, true, 0, 0)
		if opts.AzureAnonymizeIP {
			t.Fatal("an explicit azureAnonymizeIp=false must be honoured (forensics escape hatch)")
		}
	})

	t.Run("non-bool parameter cannot disable it", func(t *testing.T) {
		for _, v := range []interface{}{"false", 0, nil} {
			opts := d.newRunOptions(map[string]interface{}{"azureAnonymizeIp": v}, true, 0, 0)
			if !opts.AzureAnonymizeIP {
				t.Fatalf("azureAnonymizeIp=%#v (not a bool) must leave anonymisation ON", v)
			}
		}
	})

	t.Run("other RunOptions fields still propagate", func(t *testing.T) {
		opts := d.newRunOptions(nil, true, 42, 7)
		if !opts.IncludeDetails || opts.MaxUsers != 42 || opts.MaxGroups != 7 || !opts.Parallel {
			t.Fatalf("newRunOptions dropped a field: %+v", opts)
		}
	})

	// Behaviour above only proves the constructor. The acceptance criterion is that BOTH
	// audit paths use it (daemon.go's two former literals), so assert structurally that no
	// bare audit.RunOptions literal survives in daemon.go — the exact regression that made
	// this code dead in the first place.
	t.Run("both audit paths go through newRunOptions", func(t *testing.T) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "daemon.go", nil, 0)
		if err != nil {
			t.Fatalf("parse daemon.go: %v", err)
		}

		var offenders []string
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "RunOptions" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "audit" {
				return true
			}
			// The one inside newRunOptions is the sanctioned construction site.
			hasAnonymize := false
			for _, elt := range lit.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "AzureAnonymizeIP" {
						hasAnonymize = true
					}
				}
			}
			if !hasAnonymize {
				offenders = append(offenders, fset.Position(lit.Pos()).String())
			}
			return true
		})

		if len(offenders) > 0 {
			t.Fatalf("audit.RunOptions built without AzureAnonymizeIP at %s — route it through "+
				"newRunOptions or sign-in IPs leave the customer network unmasked",
				strings.Join(offenders, ", "))
		}
	})
}

// TestLocalCredentialNotSentToCloudSuppliedEndpoint — A_004 K4, scoped to the surface
// security proved live (T_021 VERDICTS.md §2-§3): `daemon --ldap-bind-password <secret>`
// without `--ldap-url` used to re-inject that locally-held secret on top of whatever URL
// the cloud pushed, disclosing it in plaintext to an attacker-chosen host.
func TestLocalCredentialNotSentToCloudSuppliedEndpoint(t *testing.T) {
	const localSecret = "K4-REAL-SECRET-MARKER-9f3a"
	cloudCfg := SaaSLDAPConfig{
		URL:          "ldaps://attacker.test:636",
		BindDN:       "CN=svc,CN=Users,DC=attacker,DC=test",
		BindPassword: "",
		BaseDN:       "DC=attacker,DC=test",
		TLSVerify:    true,
	}

	t.Run("local password + cloud URL is refused", func(t *testing.T) {
		d := testDaemon(&LDAPOverrides{BindPassword: localSecret})

		cfg, err := d.resolveLDAPConfig(cloudCfg)
		if err == nil {
			t.Fatal("a locally-supplied bind password must NOT be usable against a cloud-supplied URL")
		}
		if cfg.BindPassword == localSecret {
			t.Fatal("the refused config still carries the local secret")
		}
		if strings.Contains(err.Error(), localSecret) {
			t.Fatal("the error message leaks the local secret")
		}
	})

	t.Run("local password + locally pinned URL is allowed", func(t *testing.T) {
		d := testDaemon(&LDAPOverrides{BindPassword: localSecret, URL: "ldaps://dc01.corp.local:636"})

		cfg, err := d.resolveLDAPConfig(cloudCfg)
		if err != nil {
			t.Fatalf("pinning the endpoint locally must keep working: %v", err)
		}
		if cfg.URL != "ldaps://dc01.corp.local:636" {
			t.Fatalf("local URL must win, got %q", cfg.URL)
		}
		if cfg.BindPassword != localSecret {
			t.Fatal("local password must apply once the endpoint is pinned")
		}
	})

	t.Run("standard deployment is untouched", func(t *testing.T) {
		for name, d := range map[string]*Daemon{
			"no overrides at all":          testDaemon(nil),
			"overrides without a password": testDaemon(&LDAPOverrides{BaseDN: "DC=corp,DC=local"}),
		} {
			cfg, err := d.resolveLDAPConfig(cloudCfg)
			if err != nil {
				t.Fatalf("%s: cloud-managed config must keep working: %v", name, err)
			}
			if cfg.URL != cloudCfg.URL {
				t.Fatalf("%s: cloud URL should pass through, got %q", name, cfg.URL)
			}
		}
	})

	// tlsVerify: a cloud-pushed downgrade must not silently strip transport security from
	// a locally-held credential, but must keep working for the self-signed-LDAPS customers
	// that exist in the live fleet today.
	t.Run("cloud tlsVerify=false refused when a local credential is in play", func(t *testing.T) {
		insecure := cloudCfg
		insecure.TLSVerify = false
		d := testDaemon(&LDAPOverrides{BindPassword: localSecret, URL: "ldaps://dc01.corp.local:636"})

		cfg, err := d.resolveLDAPConfig(insecure)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.TLSVerify {
			t.Fatal("cloud-pushed tlsVerify=false must not disable verification while a local password is used")
		}
	})

	t.Run("cloud tlsVerify=false still honoured without a local credential", func(t *testing.T) {
		insecure := cloudCfg
		insecure.TLSVerify = false

		cfg, err := testDaemon(nil).resolveLDAPConfig(insecure)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.TLSVerify {
			t.Fatal("self-signed LDAPS customers (the live fleet's only AD config) must not break")
		}
	})

	t.Run("explicit local --ldap-tls-verify always wins", func(t *testing.T) {
		insecure := cloudCfg
		insecure.TLSVerify = false

		d := testDaemon(&LDAPOverrides{BindPassword: localSecret, URL: "ldaps://dc01.corp.local:636", TLSVerify: boolPtr(false)})
		cfg, err := d.resolveLDAPConfig(insecure)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.TLSVerify {
			t.Fatal("an explicit --ldap-tls-verify=false must be honoured")
		}

		d = testDaemon(&LDAPOverrides{TLSVerify: boolPtr(true)})
		cfg, err = d.resolveLDAPConfig(insecure)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.TLSVerify {
			t.Fatal("an explicit --ldap-tls-verify=true must override the cloud downgrade")
		}
	})
}

// TestMergeLDAPBindPassword — T_041/B_040, the third occurrence of the same class of
// bug found while searching for it: handleGUIConfigUpdateLDAP (the admin API's
// persistence callback) merges a stored password with a caller-supplied URL from
// partial params the same way admin.go's testLDAPHandler/updateLDAPConfigHandler used
// to, before this ticket's resolveAdminBindPassword guard. It is only reachable today
// through those now-guarded handlers, but the merge itself gets the same invariant
// rather than relying solely on the caller upholding it.
func TestMergeLDAPBindPassword(t *testing.T) {
	const storedSecret = "T041-REAL-DC01-SECRET-9f3a"
	const storedURL = "ldaps://dc01.corp.local:636"

	t.Run("stored password not carried over to a different URL", func(t *testing.T) {
		got := mergeLDAPBindPassword("", "ldaps://attacker.example:636", storedURL, storedSecret)
		if got == storedSecret {
			t.Fatal("the stored secret must not follow a request to a different URL")
		}
		if got != "" {
			t.Fatalf("expected an empty password for a mismatched URL, got %q", got)
		}
	})

	t.Run("stored password carried over when the URL is unchanged", func(t *testing.T) {
		got := mergeLDAPBindPassword("", storedURL, storedURL, storedSecret)
		if got != storedSecret {
			t.Fatalf("expected the stored password to be kept for the same URL, got %q", got)
		}
	})

	t.Run("an explicit param password always wins", func(t *testing.T) {
		got := mergeLDAPBindPassword("new-password", "ldaps://new-dc.corp.local:636", storedURL, storedSecret)
		if got != "new-password" {
			t.Fatalf("expected the param password, got %q", got)
		}
	})

	t.Run("nothing stored means nothing to carry over", func(t *testing.T) {
		got := mergeLDAPBindPassword("", "ldaps://new-dc.corp.local:636", "", "")
		if got != "" {
			t.Fatalf("expected empty password, got %q", got)
		}
	})
}
