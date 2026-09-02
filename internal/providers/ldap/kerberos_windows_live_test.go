//go:build windows

package ldap

import (
	"context"
	"os"
	"testing"
)

// TestIntegratedAuth_LiveDC01_SSPI is the Windows counterpart of
// kerberos_live_test.go's TestIntegratedAuth_LiveDC01 (T_047/B_036):
// proves the SSPI path binds to a real domain controller using only the
// current process's credentials (no keytab, no ccache, no password
// anywhere). Meant to be cross-compiled with `go test -c` and run directly
// on a domain-joined Windows host (see docs/configuration/
// ad-integrated-auth.md) — this repo's build/test toolchain doesn't run on
// Windows itself. Skipped unless LDAP_LIVE_DC01_TEST=1.
func TestIntegratedAuth_LiveDC01_SSPI(t *testing.T) {
	if os.Getenv("LDAP_LIVE_DC01_TEST") != "1" {
		t.Skip("set LDAP_LIVE_DC01_TEST=1 (plus LDAP_LIVE_URL, LDAP_LIVE_BASE_DN) to run against a real DC")
	}

	url := os.Getenv("LDAP_LIVE_URL")
	if url == "" {
		t.Fatal("LDAP_LIVE_URL is required (e.g. ldap://dc-01.example.com:389)")
	}
	baseDN := os.Getenv("LDAP_LIVE_BASE_DN")
	if baseDN == "" {
		t.Fatal("LDAP_LIVE_BASE_DN is required (e.g. DC=example,DC=com)")
	}

	cfg := Config{
		URL:                  url,
		BaseDN:               baseDN,
		AuthMethod:           "integrated",
		ServicePrincipalName: os.Getenv("LDAP_LIVE_SPN"), // optional override
		// BindDN / BindPassword intentionally left unset.
	}

	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.Connect(context.Background()); err != nil {
		if ce := Classify(err); ce != nil {
			t.Fatalf("integrated (SSPI) bind failed:\n%s", ce.PrettyPrint())
		}
		t.Fatalf("integrated (SSPI) bind failed: %v", err)
	}
	defer c.Close()

	info, err := c.GetDomainInfo(context.Background())
	if err != nil {
		t.Fatalf("GetDomainInfo over the SSPI-authenticated connection: %v", err)
	}
	if info == nil || info.DomainName == "" {
		t.Fatal("GetDomainInfo returned no domain name")
	}
	t.Logf("SSPI integrated auth OK: bound and queried domain %q with zero password in Config", info.DomainName)
}
