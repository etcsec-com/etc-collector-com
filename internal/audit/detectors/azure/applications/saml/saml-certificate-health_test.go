package saml

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func buildSP(name, usage string, end time.Time) types.ServicePrincipal {
	return types.ServicePrincipal{
		DisplayName: name,
		KeyCredentials: []types.AppCredential{
			{Type: "certificate", Usage: usage, Thumbprint: "ABC", EndDate: end},
		},
	}
}

func TestSAML_Expired(t *testing.T) {
	d := NewSAMLCertExpiredDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Sign", time.Now().Add(-48*time.Hour)),
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 expired, got %d", f.Count)
	}
	if f.Severity != types.SeverityCritical {
		t.Fatalf("expected critical, got %s", f.Severity)
	}
}

func TestSAML_ExpiringSoon(t *testing.T) {
	d := NewSAMLCertExpiringDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Sign", time.Now().Add(7*24*time.Hour)),
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 expiring, got %d", f.Count)
	}
	if f.Severity != types.SeverityHigh {
		t.Fatalf("expected high, got %s", f.Severity)
	}
}

func TestSAML_LongLifetime(t *testing.T) {
	d := NewSAMLCertLongLifetimeDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Sign", time.Now().Add(3*365*24*time.Hour)),
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 long lifetime, got %d", f.Count)
	}
}

func TestSAML_HealthyCertIgnored(t *testing.T) {
	expired := NewSAMLCertExpiredDetector()
	expiring := NewSAMLCertExpiringDetector()
	long := NewSAMLCertLongLifetimeDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Sign", time.Now().Add(180*24*time.Hour)), // 6 months
		},
	}
	if expired.Detect(context.Background(), data)[0].Count != 0 {
		t.Fatalf("expired should be 0")
	}
	if expiring.Detect(context.Background(), data)[0].Count != 0 {
		t.Fatalf("expiring should be 0")
	}
	if long.Detect(context.Background(), data)[0].Count != 0 {
		t.Fatalf("long should be 0")
	}
}

// T_069/B_176 — all three detectors in this file used to compare a collected
// EndDate against time.Now() independently. They now all read data.Now, so a
// single injected reference time keeps every SAML check in an audit run
// consistent with each other, and reproducible on replay.
func TestSAML_ReplayIsDeterministicAcrossRealDates(t *testing.T) {
	certExpiry := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	asOf := certExpiry.Add(-10 * 24 * time.Hour) // 10 days before expiry — inside the 30-day window

	detect := func(now time.Time) types.Finding {
		data := &audit.DetectorData{
			Now:                    now,
			AzureServicePrincipals: []types.ServicePrincipal{buildSP("sp1", "Sign", certExpiry)},
		}
		return NewSAMLCertExpiringDetector().Detect(context.Background(), data)[0]
	}

	first := detect(asOf)
	time.Sleep(2 * time.Millisecond)
	second := detect(asOf)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("replaying the identical frozen input produced different findings:\nfirst:  %+v\nsecond: %+v", first, second)
	}

	shifted := detect(asOf.AddDate(2, 0, 0))
	// Shifting only `now` (not the certificate's own EndDate) changes the real
	// gap-to-expiry — this is not a replay of the same capture, it is a
	// different point in the certificate's lifecycle, so the result legitimately
	// differs. What matters is that it is DETERMINED BY that gap, not by which
	// real calendar day the test happened to run on: expiry is now ~2 years in
	// the past relative to `now`, well outside the 30-day expiring-soon window.
	if shifted.Count != 0 {
		t.Fatalf("expected 0 once the injected `now` moves the certificate's expiry outside the window, got %+v", shifted)
	}
}

func TestSAML_NonSigningUsageIgnored(t *testing.T) {
	d := NewSAMLCertExpiredDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Encrypt", time.Now().Add(-48*time.Hour)),
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for non-signing usage, got %d", f.Count)
	}
}
