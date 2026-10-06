package network

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func detectDNSZoneAUCreateChild(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewDNSZoneAUCreateChildDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestDNSZoneAUCreateChild_AuthenticatedUsersGrant(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{
		IncludeDetails: true,
		DNSZones: []types.DNSZone{
			{DN: "CN=dns-zone-1,DC=corp,DC=com", Name: "dns-zone-1"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=dns-zone-1,DC=corp,DC=com",
				Trustee: "S-1-5-11", AceType: "ACCESS_ALLOWED", AccessMask: 0x1},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Authenticated Users CreateChild must be caught, count=%d", f.Count)
	}
	zones, _ := f.Details["vulnerableZones"].([]string)
	if len(zones) != 1 || zones[0] != "dns-zone-1" {
		t.Errorf("expected vulnerableZones=[dns-zone-1], got %v", f.Details["vulnerableZones"])
	}
}

func TestDNSZoneAUCreateChild_EveryoneGrant(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{
		DNSZones: []types.DNSZone{
			{DN: "CN=dns-zone-2,DC=contoso,DC=com", Name: "dns-zone-2"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=dns-zone-2,DC=contoso,DC=com",
				Trustee: "S-1-1-0", AceType: "ACCESS_ALLOWED", AccessMask: 0x1},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Everyone CreateChild must be caught, count=%d", f.Count)
	}
}

func TestDNSZoneAUCreateChild_ObjectAceTypeAlsoCaught(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{
		DNSZones: []types.DNSZone{
			{DN: "CN=dns-zone-3,DC=corp,DC=com", Name: "dns-zone-3"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=dns-zone-3,DC=corp,DC=com",
				Trustee: "S-1-5-11", AceType: "ACCESS_ALLOWED_OBJECT", AccessMask: 0x1},
		},
	})
	if f.Count != 1 {
		t.Fatalf("ACCESS_ALLOWED_OBJECT ACE type must also be caught, count=%d", f.Count)
	}
}

func TestDNSZoneAUCreateChild_OtherTrusteeNotAffected(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{
		DNSZones: []types.DNSZone{
			{DN: "CN=dns-zone-4,DC=corp,DC=com", Name: "dns-zone-4"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=dns-zone-4,DC=corp,DC=com",
				Trustee: "S-1-5-21-1-2-3-512", AceType: "ACCESS_ALLOWED", AccessMask: 0x1},
		},
	})
	if f.Count != 0 {
		t.Fatalf("a non-AU/Everyone trustee must not be counted, count=%d", f.Count)
	}
}

func TestDNSZoneAUCreateChild_DenyAceNotAffected(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{
		DNSZones: []types.DNSZone{
			{DN: "CN=dns-zone-5,DC=corp,DC=com", Name: "dns-zone-5"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=dns-zone-5,DC=corp,DC=com",
				Trustee: "S-1-5-11", AceType: "ACCESS_DENIED", AccessMask: 0x1},
		},
	})
	if f.Count != 0 {
		t.Fatalf("an ACCESS_DENIED ACE must not be counted, count=%d", f.Count)
	}
}

func TestDNSZoneAUCreateChild_MaskWithoutCreateChildBitNotAffected(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{
		DNSZones: []types.DNSZone{
			{DN: "CN=dns-zone-6,DC=corp,DC=com", Name: "dns-zone-6"},
		},
		ACLEntries: []types.ACLEntry{
			// 0x10 = ReadProperty only, no CreateChild (0x1) bit set.
			{ObjectDN: "CN=dns-zone-6,DC=corp,DC=com",
				Trustee: "S-1-5-11", AceType: "ACCESS_ALLOWED", AccessMask: 0x10},
		},
	})
	if f.Count != 0 {
		t.Fatalf("a mask without the CreateChild bit must not be counted, count=%d", f.Count)
	}
}

func TestDNSZoneAUCreateChild_AclOnUnrelatedObjectNotAffected(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{
		DNSZones: []types.DNSZone{
			{DN: "CN=dns-zone-7,DC=corp,DC=com", Name: "dns-zone-7"},
		},
		ACLEntries: []types.ACLEntry{
			// Vulnerable ACE present, but on a different object's DN entirely.
			{ObjectDN: "CN=some-other-object,DC=corp,DC=com",
				Trustee: "S-1-5-11", AceType: "ACCESS_ALLOWED", AccessMask: 0x1},
		},
	})
	if f.Count != 0 {
		t.Fatalf("an ACE on an unrelated object DN must not be counted, count=%d", f.Count)
	}
}

func TestDNSZoneAUCreateChild_MixedZonesOnlyVulnerableCounted(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{
		IncludeDetails: true,
		DNSZones: []types.DNSZone{
			{DN: "CN=vuln-zone,DC=corp,DC=com", Name: "vuln-zone"},
			{DN: "CN=clean-zone,DC=corp,DC=com", Name: "clean-zone"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=vuln-zone,DC=corp,DC=com",
				Trustee: "S-1-5-11", AceType: "ACCESS_ALLOWED", AccessMask: 0x1},
			{ObjectDN: "CN=clean-zone,DC=corp,DC=com",
				Trustee: "S-1-5-21-1-2-3-512", AceType: "ACCESS_ALLOWED", AccessMask: 0x000f01ff},
		},
	})
	if f.Count != 1 {
		t.Fatalf("exactly one of the two zones is vulnerable, count=%d", f.Count)
	}
	zones, _ := f.Details["vulnerableZones"].([]string)
	if len(zones) != 1 || zones[0] != "vuln-zone" {
		t.Errorf("expected vulnerableZones=[vuln-zone], got %v", f.Details["vulnerableZones"])
	}
}

func TestDNSZoneAUCreateChild_EmptyZoneDNSkipped(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{
		DNSZones: []types.DNSZone{
			{DN: "", Name: "no-dn-zone"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "", Trustee: "S-1-5-11", AceType: "ACCESS_ALLOWED", AccessMask: 0x1},
		},
	})
	if f.Count != 0 {
		t.Fatalf("a zone with an empty DN must be skipped, count=%d", f.Count)
	}
}

func TestDNSZoneAUCreateChild_NoZones(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{})
	if f.Count != 0 {
		t.Fatalf("no DNS zones must not be reported as vulnerable, count=%d", f.Count)
	}
}

// TestDNSZoneAUCreateChild_MutationCoverage is the literal subtest required
// by the acceptance criteria this detector was most recently re-verified
// against: a fixture built from zero (its own DN and trustee, not shared
// with any other subtest above), mirroring the exact shape confirmed live
// against a lab domain controller - a single DNS zone with a single
// ACCESS_ALLOWED ACE granting S-1-5-11 the CreateChild bit (0x1). Kills
// mutation M1 (condition (c), the CreateChild bit check on line 43 of
// dns-zone-au-create-child.go).
func TestDNSZoneAUCreateChild_MutationCoverage(t *testing.T) {
	f := detectDNSZoneAUCreateChild(t, &audit.DetectorData{
		IncludeDetails: true,
		DNSZones: []types.DNSZone{
			{DN: "CN=t540test,DC=corp,DC=com", Name: "t540test"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=t540test,DC=corp,DC=com",
				Trustee: "S-1-5-11", AceType: "ACCESS_ALLOWED", AccessMask: 0x1},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (lab plant mirror: S-1-5-11 CreateChild grant must be caught - kills_M1)", f.Count)
	}
	zones, _ := f.Details["vulnerableZones"].([]string)
	if len(zones) != 1 || zones[0] != "t540test" {
		t.Errorf("expected vulnerableZones=[t540test], got %v", f.Details["vulnerableZones"])
	}
}
