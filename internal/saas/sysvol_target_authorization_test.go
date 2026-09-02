package saas

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"testing"
)

// fakeSRV/fakeIPAddr build canned DNS responses so these tests never touch
// real DNS.
func fakeSRV(targets ...string) (string, []*net.SRV, error) {
	srvs := make([]*net.SRV, len(targets))
	for i, t := range targets {
		srvs[i] = &net.SRV{Target: t, Port: 389}
	}
	return "", srvs, nil
}

func withFakeDNS(t *testing.T, lookupSRV func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error), lookupIPAddr func(ctx context.Context, host string) ([]net.IPAddr, error)) {
	t.Helper()
	origSRV, origIP := sysvolLookupSRV, sysvolLookupIPAddr
	sysvolLookupSRV = lookupSRV
	if lookupIPAddr != nil {
		sysvolLookupIPAddr = lookupIPAddr
	}
	t.Cleanup(func() {
		sysvolLookupSRV = origSRV
		sysvolLookupIPAddr = origIP
	})
}

// TestIsAuthorizedSYSVOLTarget_MatchesPublishedDC — B_138 (T_081). A host
// that IS one of the domain's own _ldap._tcp SRV targets must be authorized —
// the normal case for every real deployment (this collector runs ON a DC for
// the domain it audits).
func TestIsAuthorizedSYSVOLTarget_MatchesPublishedDC(t *testing.T) {
	withFakeDNS(t, func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
		if service != "ldap" || proto != "tcp" || name != "corp.example.com" {
			t.Fatalf("unexpected SRV lookup: %s/%s/%s", service, proto, name)
		}
		return fakeSRV("dc1.corp.example.com.", "dc2.corp.example.com.")
	}, nil)

	if !isAuthorizedSYSVOLTarget(context.Background(), "dc1.corp.example.com", "corp.example.com") {
		t.Fatal("dc1.corp.example.com is a published SRV target and must be authorized")
	}
}

// TestIsAuthorizedSYSVOLTarget_RejectsArbitraryHost — B_138 (T_081), the
// exact primitive this fix closes: a cloud-supplied host that is NOT one of
// the domain's own published domain controllers must be rejected, even
// though it parses as a perfectly valid hostname.
func TestIsAuthorizedSYSVOLTarget_RejectsArbitraryHost(t *testing.T) {
	withFakeDNS(t, func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
		return fakeSRV("dc1.corp.example.com.")
	}, nil)

	if isAuthorizedSYSVOLTarget(context.Background(), "attacker.evil.example", "corp.example.com") {
		t.Fatal("attacker.evil.example is not a published DC for corp.example.com and must not be authorized")
	}
}

// TestIsAuthorizedSYSVOLTarget_MatchesByIP — an operator using an IP-literal
// LDAP URL (common when internal DNS doesn't resolve the DC by name from
// this host) must not be broken by this fix: an IP that resolves to one of
// the SRV targets is authorized.
func TestIsAuthorizedSYSVOLTarget_MatchesByIP(t *testing.T) {
	withFakeDNS(t, func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
		return fakeSRV("dc1.corp.example.com.")
	}, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "dc1.corp.example.com." {
			t.Fatalf("unexpected A/AAAA lookup for %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
	})

	if !isAuthorizedSYSVOLTarget(context.Background(), "10.0.0.5", "corp.example.com") {
		t.Fatal("10.0.0.5 resolves to a published SRV target and must be authorized")
	}
}

// TestIsAuthorizedSYSVOLTarget_FailsClosedOnDNSError — a DNS error (e.g. this
// resolver can't reach the domain's DNS at all) must NOT be treated as
// "can't verify, so allow" — it must fail closed, same posture as K12's
// replay-window fix elsewhere in this ticket.
func TestIsAuthorizedSYSVOLTarget_FailsClosedOnDNSError(t *testing.T) {
	withFakeDNS(t, func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
		return "", nil, errors.New("no such host")
	}, nil)

	if isAuthorizedSYSVOLTarget(context.Background(), "dc1.corp.example.com", "corp.example.com") {
		t.Fatal("a DNS lookup error must fail closed (not authorized), not open")
	}
}

// TestIsAuthorizedSYSVOLTarget_FailsClosedOnEmptyRecordSet — a domain with no
// published LDAP SRV records (misconfigured DNS, or a non-AD domain string)
// must also fail closed rather than vacuously authorizing everything.
func TestIsAuthorizedSYSVOLTarget_FailsClosedOnEmptyRecordSet(t *testing.T) {
	withFakeDNS(t, func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
		return fakeSRV() // no records
	}, nil)

	if isAuthorizedSYSVOLTarget(context.Background(), "dc1.corp.example.com", "corp.example.com") {
		t.Fatal("an empty SRV record set must fail closed")
	}
}

// TestIsAuthorizedSYSVOLTarget_RejectsEmptyInputs — defensive: an empty host
// or domain (e.g. a config parsed from a command with missing fields) must
// never be treated as authorized.
func TestIsAuthorizedSYSVOLTarget_RejectsEmptyInputs(t *testing.T) {
	if isAuthorizedSYSVOLTarget(context.Background(), "", "corp.example.com") {
		t.Fatal("empty host must not be authorized")
	}
	if isAuthorizedSYSVOLTarget(context.Background(), "dc1.corp.example.com", "") {
		t.Fatal("empty domain must not be authorized")
	}
}

// TestSMBConnectSitesCallAuthorizationCheck — B_138 (T_081), a wiring lock:
// static proof that both places daemon.go dials SMB/SYSVOL
// (initLDAPProvider, reached at startup and on reconnect-retry from
// persisted config; executeUpdateConfigAD, reached directly from an
// incoming UPDATE_CONFIG_AD command) actually call
// isAuthorizedSYSVOLTarget before smb.NewClient — not just today, but if
// either function is edited later. Catches the regression of someone
// re-adding an unguarded smb.NewClient call without the check.
func TestSMBConnectSitesCallAuthorizationCheck(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}

	for _, funcName := range []string{"initLDAPProvider", "executeUpdateConfigAD"} {
		t.Run(funcName, func(t *testing.T) {
			var fn *ast.FuncDecl
			for _, decl := range f.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == funcName {
					fn = fd
					break
				}
			}
			if fn == nil {
				t.Fatalf("%s not found in daemon.go", funcName)
			}

			callsAuth := false
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "isAuthorizedSYSVOLTarget" {
					callsAuth = true
				}
				return true
			})
			if !callsAuth {
				t.Fatalf("%s does not call isAuthorizedSYSVOLTarget — the SMB/SYSVOL dial in this function would be unguarded again", funcName)
			}
		})
	}
}
