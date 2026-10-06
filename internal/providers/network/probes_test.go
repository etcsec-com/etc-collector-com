package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// fakeDNSError simulates "hostname does not resolve" - the exact failure
// mode this fixes: a probe target's hostname can't be resolved from
// an agentless collector outside the domain's DNS, even though the DC
// itself is reachable by IP.
func fakeDNSError(host string) error {
	return &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// withSpoolerDialer temporarily swaps the dialer probeSpooler uses for its
// port-445 TCP check, restoring the original afterwards.
func withSpoolerDialer(t *testing.T, dial func(network, address string, timeout time.Duration) (net.Conn, error)) {
	t.Helper()
	orig := spoolerPortDialer
	spoolerPortDialer = dial
	t.Cleanup(func() { spoolerPortDialer = orig })
}

// TestProbeSpooler_PortClosed covers the one case this probe can be
// confident about: SMB unreachable rules the spoolss pipe out too, since
// there is no path to it without SMB.
func TestProbeSpooler_PortClosed(t *testing.T) {
	withSpoolerDialer(t, func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	})

	results, warnings := probeSpooler(context.Background(), []string{"dc1.example.com"})
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.SpoolerRunning {
		t.Error("SpoolerRunning must be false when SMB is unreachable")
	}
	if !r.Determined {
		t.Error("Determined must be true when SMB is unreachable - that's the one case this probe can rule out cleanly")
	}
	if r.Error == "" {
		t.Error("Error must explain why SMB was unreachable")
	}
}

// TestProbeSpooler_PortOpenIsNotProof is RED on the pre-fix behavior: the old
// probeSpooler set SpoolerRunning=true as soon as TCP 445 answered, which is
// a guaranteed false positive since SMB is open on every domain controller
// regardless of Print Spooler state. After the fix, an open port with no
// authenticated pipe check must report "not determined", never "running".
func TestProbeSpooler_PortOpenIsNotProof(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	withSpoolerDialer(t, func(network, address string, timeout time.Duration) (net.Conn, error) {
		// Simulate "port 445 is open" by dialing the fake listener instead,
		// regardless of the (unreachable in CI) address the caller asked for.
		return net.DialTimeout(network, ln.Addr().String(), timeout)
	})

	results, _ := probeSpooler(context.Background(), []string{"dc1.example.com"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.SpoolerRunning {
		t.Fatal("an open SMB port alone must never set SpoolerRunning=true - that's the false positive this test pins")
	}
	if r.Determined {
		t.Error("Determined must be false: no authenticated session was used to check the spoolss pipe")
	}
	if r.Error == "" {
		t.Error("Error must explain that the pipe was not verified")
	}
}

func TestProbeSpooler_MultipleDCs(t *testing.T) {
	withSpoolerDialer(t, func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	})

	results, _ := probeSpooler(context.Background(), []string{"dc1.example.com", "dc2.example.com"})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].DCHostname != "dc1.example.com" || results[1].DCHostname != "dc2.example.com" {
		t.Errorf("unexpected hostnames: %+v", results)
	}
}

// TestProbeSpooler_HostnameUnresolved is RED on the pre-fix behavior: a DC
// hostname that never resolves was reported identically to a real "SMB
// unreachable" negative (Determined=true), even though the probe never
// reached the network at all. After the fix this must be Determined=false
// with a visible warning naming the unresolved hostname.
func TestProbeSpooler_HostnameUnresolved(t *testing.T) {
	withSpoolerDialer(t, func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, fakeDNSError("dc1.example.com")
	})

	results, warnings := probeSpooler(context.Background(), []string{"dc1.example.com"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Determined {
		t.Error("Determined must be false: the hostname never resolved, SMB was never reached")
	}
	if r.Error == "" {
		t.Error("Error must explain the DNS resolution failure")
	}
	if len(warnings) != 1 {
		t.Fatalf("expected exactly 1 warning, got %v", warnings)
	}
	if warnings[0].Code != "PROBE_DC_HOSTNAME_UNRESOLVED" {
		t.Errorf("expected PROBE_DC_HOSTNAME_UNRESOLVED, got %s", warnings[0].Code)
	}
	if len(warnings[0].AffectedDetectors) != 1 || warnings[0].AffectedDetectors[0] != "DC_SPOOLER_ACCESSIBLE" {
		t.Errorf("expected AffectedDetectors=[DC_SPOOLER_ACCESSIBLE], got %v", warnings[0].AffectedDetectors)
	}
}

// --- ESC8 HTTP probe ---

func withESC8Dialer(t *testing.T, dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	t.Helper()
	orig := esc8DialContext
	esc8DialContext = dial
	t.Cleanup(func() { esc8DialContext = orig })
}

// TestProbeESC8_HostnameUnresolved is the red case: a DC
// hostname that doesn't resolve must produce a visible, explicit warning and
// a result that can't be confused with "checked, not vulnerable".
func TestProbeESC8_HostnameUnresolved(t *testing.T) {
	withESC8Dialer(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fakeDNSError("dc1.example.com")
	})

	results, warnings := probeESC8(context.Background(), []string{"dc1.example.com"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Determined {
		t.Error("Determined must be false: the hostname never resolved, the probe never reached the network")
	}
	if r.WebEnrollment {
		t.Error("WebEnrollment must be false when the probe never ran")
	}
	if r.Error == "" {
		t.Error("Error must explain the DNS resolution failure")
	}
	if len(warnings) != 1 {
		t.Fatalf("expected exactly 1 warning, got %v", warnings)
	}
	if warnings[0].Code != "PROBE_DC_HOSTNAME_UNRESOLVED" {
		t.Errorf("expected PROBE_DC_HOSTNAME_UNRESOLVED, got %s", warnings[0].Code)
	}
	if len(warnings[0].AffectedDetectors) != 1 || warnings[0].AffectedDetectors[0] != "ESC8_HTTP_ENROLLMENT" {
		t.Errorf("expected AffectedDetectors=[ESC8_HTTP_ENROLLMENT], got %v", warnings[0].AffectedDetectors)
	}
}

// TestProbeESC8_ReachableHostWorks is the green case: once the target is
// actually reachable, the probe must run and produce a determined result -
// no warning, real HTTP status observed.
func TestProbeESC8_ReachableHostWorks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	withESC8Dialer(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ts.Listener.Addr().String())
	})

	results, warnings := probeESC8(context.Background(), []string{"dc1.example.com"})
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for a reachable host, got %v", warnings)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if !r.Determined {
		t.Error("Determined must be true: the probe reached the host and got an HTTP response")
	}
	if r.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", r.StatusCode)
	}
	if r.WebEnrollment {
		t.Error("404 must not be flagged as web enrollment exposed")
	}
}

// --- DNS zone transfer probe ---

func withZoneTransferDialer(t *testing.T, dial func(network, address string, timeout time.Duration) (net.Conn, error)) {
	t.Helper()
	orig := zoneTransferDialer
	zoneTransferDialer = dial
	t.Cleanup(func() { zoneTransferDialer = orig })
}

func TestProbeZoneTransfer_HostnameUnresolved(t *testing.T) {
	withZoneTransferDialer(t, func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, fakeDNSError("dc1.example.com")
	})

	zones := []types.DNSZone{{Name: "example.com"}}
	results, warnings := probeZoneTransfer(context.Background(), zones, []string{"dc1.example.com"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Determined {
		t.Error("Determined must be false: the DC hostname never resolved")
	}
	if r.Allowed {
		t.Error("Allowed must be false when the probe never ran")
	}
	if len(warnings) != 1 {
		t.Fatalf("expected exactly 1 warning, got %v", warnings)
	}
	if warnings[0].Code != "PROBE_DC_HOSTNAME_UNRESOLVED" {
		t.Errorf("expected PROBE_DC_HOSTNAME_UNRESOLVED, got %s", warnings[0].Code)
	}
	if len(warnings[0].AffectedDetectors) != 1 || warnings[0].AffectedDetectors[0] != "DNS_ZONE_TRANSFER_UNRESTRICTED" {
		t.Errorf("expected AffectedDetectors=[DNS_ZONE_TRANSFER_UNRESTRICTED], got %v", warnings[0].AffectedDetectors)
	}
}

// TestProbeZoneTransfer_ReachableHostWorks is the green case: a reachable
// DNS server that refuses the transfer must be reported as a determined,
// non-vulnerable result - not conflated with the unresolvable case.
func TestProbeZoneTransfer_ReachableHostWorks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	withZoneTransferDialer(t, func(network, address string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, ln.Addr().String(), timeout)
	})

	zones := []types.DNSZone{{Name: "example.com"}}
	results, warnings := probeZoneTransfer(context.Background(), zones, []string{"dc1.example.com"})
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for a reachable host, got %v", warnings)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if !r.Determined {
		t.Error("Determined must be true: the probe reached the DNS server")
	}
	if r.Allowed {
		t.Error("a connection that closes immediately must not be reported as zone transfer allowed")
	}
}

// --- LDAPS weak-TLS probe ---

func withLDAPSDialer(t *testing.T, dial func(dialer *net.Dialer, network, addr string, config *tls.Config) (*tls.Conn, error)) {
	t.Helper()
	orig := ldapsTLSDialer
	ldapsTLSDialer = dial
	t.Cleanup(func() { ldapsTLSDialer = orig })
}

func withLDAPPlainDialer(t *testing.T, dial func(network, address string, timeout time.Duration) (net.Conn, error)) {
	t.Helper()
	orig := ldapPlainDialer
	ldapPlainDialer = dial
	t.Cleanup(func() { ldapPlainDialer = orig })
}

// TestProbeLDAPSTLS_HostnameUnresolved also checks that the 389 fallback is
// skipped: retrying the same unresolvable hostname on a different port can't
// produce a different DNS answer.
func TestProbeLDAPSTLS_HostnameUnresolved(t *testing.T) {
	withLDAPSDialer(t, func(dialer *net.Dialer, network, addr string, config *tls.Config) (*tls.Conn, error) {
		return nil, fakeDNSError("dc1.example.com")
	})
	plainCalled := false
	withLDAPPlainDialer(t, func(network, address string, timeout time.Duration) (net.Conn, error) {
		plainCalled = true
		return nil, fmt.Errorf("should not be called")
	})

	results, warnings := probeLDAPSTLS(context.Background(), []string{"dc1.example.com"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Determined {
		t.Error("Determined must be false: the hostname never resolved")
	}
	if r.Port != 636 {
		t.Errorf("expected port to stay 636 (no point retrying 389 for the same unresolvable name), got %d", r.Port)
	}
	if plainCalled {
		t.Error("the 389 fallback must not be attempted when 636 already failed to resolve the same hostname")
	}
	if len(warnings) != 1 {
		t.Fatalf("expected exactly 1 warning, got %v", warnings)
	}
	if warnings[0].Code != "PROBE_DC_HOSTNAME_UNRESOLVED" {
		t.Errorf("expected PROBE_DC_HOSTNAME_UNRESOLVED, got %s", warnings[0].Code)
	}
	if len(warnings[0].AffectedDetectors) != 1 || warnings[0].AffectedDetectors[0] != "DC_LDAPS_WEAK_TLS" {
		t.Errorf("expected AffectedDetectors=[DC_LDAPS_WEAK_TLS], got %v", warnings[0].AffectedDetectors)
	}
}

// TestProbeLDAPSTLS_ReachableHostWorks is the green case: 636 reachable but
// rejecting weak TLS (a real network answer, not a resolution failure) falls
// through to the 389 STARTTLS attempt, which must also be treated as
// determined once it reaches a real listener.
func TestProbeLDAPSTLS_ReachableHostWorks(t *testing.T) {
	withLDAPSDialer(t, func(dialer *net.Dialer, network, addr string, config *tls.Config) (*tls.Conn, error) {
		return nil, fmt.Errorf("tls: handshake failure")
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	withLDAPPlainDialer(t, func(network, address string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, ln.Addr().String(), timeout)
	})

	results, warnings := probeLDAPSTLS(context.Background(), []string{"dc1.example.com"})
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for a reachable host, got %v", warnings)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if !r.Determined {
		t.Error("Determined must be true: the probe reached the host on port 389")
	}
	if r.WeakTLS {
		t.Error("must not report WeakTLS from a connection that never completed STARTTLS")
	}
}
