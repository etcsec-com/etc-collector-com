package network

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_046 / B_049 — DNSSEC_NOT_ENABLED used to treat "no DNS zone data
// collected" as "DNSSEC not enabled", the same "absence of measurement =
// negative finding" bug fixed on SMB_SIGNING_DISABLED. Sibling detectors in
// this package (dns-dynamic-update.go, dns-wildcard.go) already got this
// right — this brings dnssec.go in line.

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

func TestDnssec_MeasuredUnsignedZoneFires(t *testing.T) {
	f := detectDnssec(t, &audit.DetectorData{
		IncludeDetails: true,
		DNSZones:       []types.DNSZone{{Name: "example.com", DNSSECEnabled: false}},
	})
	if f.Count != 1 {
		t.Fatalf("measured + unsigned zone must fire, count=%d", f.Count)
	}
}

func TestDnssec_MeasuredAllSignedDoesNotFire(t *testing.T) {
	f := detectDnssec(t, &audit.DetectorData{
		IncludeDetails: true,
		DNSZones:       []types.DNSZone{{Name: "example.com", DNSSECEnabled: true}},
	})
	if f.Count != 0 {
		t.Fatalf("measured + all zones signed must not fire, count=%d", f.Count)
	}
}
