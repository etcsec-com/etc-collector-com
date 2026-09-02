//go:build !windows

package ldap

import (
	"context"
	"os"
	"testing"
)

// TestIntegratedAuth_LiveDC01 is an opt-in integration test proving the
// Linux/macOS GSSAPI path (T_047/B_036) binds to a REAL Active Directory
// domain controller with zero password anywhere in Config — the whole point
// of the ticket. The frozen LDAP-replay bench (docs/testing/snapshots/)
// cannot exercise this: it replays a recorded wire capture, not a live
// Kerberos negotiation (see the ticket's own cadrage). This is the
// substitute: skipped by default (no live-network/Kerberos dependency in
// normal `go test ./...` or CI), opt in with LDAP_LIVE_DC01_TEST=1 against a
// real domain after populating the ambient ticket cache (kinit) or pointing
// KerberosKeytab at a real keytab. See
// docs/configuration/ad-integrated-auth.md for the full setup.
func TestIntegratedAuth_LiveDC01(t *testing.T) {
	if os.Getenv("LDAP_LIVE_DC01_TEST") != "1" {
		t.Skip("set LDAP_LIVE_DC01_TEST=1 (plus LDAP_LIVE_URL, LDAP_LIVE_BASE_DN, and a populated Kerberos ticket cache or keytab) to run against a real DC")
	}

	url := os.Getenv("LDAP_LIVE_URL")
	if url == "" {
		t.Fatal("LDAP_LIVE_URL is required (e.g. ldap://192.0.2.83:389 — GSSAPI provides its own signing/sealing, LDAPS is not required)")
	}
	baseDN := os.Getenv("LDAP_LIVE_BASE_DN")
	if baseDN == "" {
		t.Fatal("LDAP_LIVE_BASE_DN is required (e.g. DC=example,DC=com)")
	}

	cfg := Config{
		URL:        url,
		BaseDN:     baseDN,
		AuthMethod: "integrated",
		// BindDN / BindPassword intentionally left unset — that's the
		// acceptance criterion: the collector binds without a stored secret.
		KerberosKeytab:       os.Getenv("LDAP_LIVE_KEYTAB"),           // optional
		KerberosPrincipal:    os.Getenv("LDAP_LIVE_KEYTAB_PRINCIPAL"), // optional, required with KerberosKeytab
		Krb5Config:           os.Getenv("LDAP_LIVE_KRB5_CONFIG"),      // optional override of /etc/krb5.conf
		KerberosCCache:       os.Getenv("LDAP_LIVE_KRB5_CCACHE"),      // optional override of KRB5CCNAME/OS default
		ServicePrincipalName: os.Getenv("LDAP_LIVE_SPN"),              // optional override, e.g. when LDAP_LIVE_URL uses an IP (AD registers SPNs by hostname, not IP)
	}

	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.Connect(context.Background()); err != nil {
		if ce := Classify(err); ce != nil {
			t.Fatalf("integrated bind failed:\n%s", ce.PrettyPrint())
		}
		t.Fatalf("integrated bind failed: %v", err)
	}
	defer c.Close()

	if !c.IsConnected() {
		t.Fatal("Connect() returned nil error but IsConnected() is false")
	}

	// Prove the session is actually usable, not just that the bind
	// succeeded: a real LDAP search over the GSSAPI-authenticated
	// connection.
	info, err := c.GetDomainInfo(context.Background())
	if err != nil {
		t.Fatalf("GetDomainInfo over the integrated-auth connection: %v", err)
	}
	if info == nil || info.DomainName == "" {
		t.Fatal("GetDomainInfo returned no domain name")
	}
	t.Logf("integrated auth OK: bound and queried domain %q with zero password in Config", info.DomainName)
}
