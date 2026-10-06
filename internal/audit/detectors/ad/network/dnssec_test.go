package network

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RETIRED - DNSSEC_NOT_ENABLED read zone.DNSSECEnabled,
// itself derived from a misread LDAP dNSProperty propId (0x10 =
// DSPROPERTY_ZONE_NOREFRESH_INTERVAL, not DSPROPERTY_ZONE_SECURE_TIME) that
// never encoded DNSSEC signing state (RRSIG/DNSKEY) in the first place -
// see internal/providers/ldap/client.go GetDNSZones. No provider collects a
// trustworthy signal today, so per doctrine the detector must never emit a
// verdict it can't measure - not even for "obviously unsigned" input.

func detectDnssec(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewDnssecDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestDnssec_NoZoneDataDoesNotFire(t *testing.T) {
	f := detectDnssec(t, &audit.DetectorData{IncludeDetails: true})
	if f.Count != 0 {
		t.Fatalf("no DNS zone data must not be reported as a finding, count=%d", f.Count)
	}
}

// TestDnssec_NeverFiresEvenWithZoneData is RED on today's code: the current
// Detect() sets Count=1 for this exact input (an "unsigned" zone) because it
// still trusts zone.DNSSECEnabled - the field this proves is not a
// real DNSSEC signal. After the patch, Detect() is retired and never emits,
// so Count must be 0 regardless of what DNSZones carries.
func TestDnssec_NeverFiresEvenWithZoneData(t *testing.T) {
	f := detectDnssec(t, &audit.DetectorData{
		IncludeDetails: true,
		DNSZones:       []types.DNSZone{{Name: "example.com", DNSSECEnabled: false}},
	})
	if f.Count != 0 {
		t.Fatalf("retired detector must never fire, count=%d", f.Count)
	}
}

// TestDnssec_NotRegistered pins that the detector is deregistered, not just
// silenced - a client running a real audit must never see this ID.
func TestDnssec_NotRegistered(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("DNSSEC_NOT_ENABLED"); ok {
		t.Fatal("DNSSEC_NOT_ENABLED must not be registered (RETIRER)")
	}
}
