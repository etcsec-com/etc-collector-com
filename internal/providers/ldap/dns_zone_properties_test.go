package ldap

import (
	"encoding/base64"
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// buildDNSProperty encodes a synthetic [MS-DNSP] 2.3.2.1 dnsProperty blob:
// DataLength, NameLength, Flag, Version, Id (each a little-endian DWORD),
// followed by `data` and an empty Name.
func buildDNSProperty(id uint32, data []byte) []byte {
	b := make([]byte, 20+len(data))
	putU32 := func(off int, v uint32) {
		b[off] = byte(v)
		b[off+1] = byte(v >> 8)
		b[off+2] = byte(v >> 16)
		b[off+3] = byte(v >> 24)
	}
	putU32(0, uint32(len(data))) // DataLength
	putU32(4, 0)                 // NameLength
	putU32(8, 0)                 // Flag
	putU32(12, 1)                // Version
	putU32(16, id)               // Id
	copy(b[20:], data)
	return b
}

// TestApplyDNSZoneProperties_AllowUpdate: before the fix, the
// property Id was read from bytes 4-7 (NameLength, always 0 for a zone-level
// property with no name), so DSPROPERTY_ZONE_ALLOW_UPDATE (Id=2) could never
// match and DynamicUpdate stayed "unknown" regardless of the real zone
// configuration. The Id lives at byte 16.
func TestApplyDNSZoneProperties_AllowUpdate(t *testing.T) {
	cases := []struct {
		name       string
		updateFlag byte
		want       string
	}{
		{"ZONE_UPDATE_OFF", 0, "none"},
		{"ZONE_UPDATE_UNSECURE", 1, "nonsecure"},
		{"ZONE_UPDATE_SECURE", 2, "secure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zone := &types.DNSZone{DynamicUpdate: "unknown"}
			prop := buildDNSProperty(0x00000002, []byte{tc.updateFlag, 0, 0, 0})
			applyDNSZoneProperties(zone, [][]byte{prop})
			if zone.DynamicUpdate != tc.want {
				t.Fatalf("DynamicUpdate = %q, want %q", zone.DynamicUpdate, tc.want)
			}
		})
	}
}

// TestApplyDNSZoneProperties_RealDC01Capture reproduces the exact
// DSPROPERTY_ZONE_ALLOW_UPDATE blob captured live from a domain controller (
// 2026-09-08), a zone actually configured NonsecureAndSecure
// (docs/security-validation/results/t163-manual/VERDICT-T163.md). Before the
// fix this decoded to DynamicUpdate="unknown"; after, "nonsecure".
func TestApplyDNSZoneProperties_RealDC01Capture(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString("AQAAAAAAAAAAAAAAAQAAAAIAAAABAAAAAA==")
	if err != nil {
		t.Fatalf("failed to decode captured blob: %v", err)
	}
	zone := &types.DNSZone{DynamicUpdate: "unknown"}
	applyDNSZoneProperties(zone, [][]byte{raw})
	if zone.DynamicUpdate != "nonsecure" {
		t.Fatalf("DynamicUpdate = %q, want %q (real DC01 zone is NonsecureAndSecure)", zone.DynamicUpdate, "nonsecure")
	}
}

// TestApplyDNSZoneProperties_OtherPropertiesIgnored guards against the
// unrelated NOREFRESH_INTERVAL property (Id=0x10) being mistaken for
// ALLOW_UPDATE, and against a too-short blob panicking instead of being
// skipped.
func TestApplyDNSZoneProperties_OtherPropertiesIgnored(t *testing.T) {
	zone := &types.DNSZone{DynamicUpdate: "unknown"}
	noRefresh := buildDNSProperty(0x00000010, []byte{0xa8, 0, 0, 0}) // 168 hours
	tooShort := []byte{1, 2, 3}
	applyDNSZoneProperties(zone, [][]byte{noRefresh, tooShort})
	if zone.DynamicUpdate != "unknown" {
		t.Fatalf("DynamicUpdate = %q, want unchanged %q", zone.DynamicUpdate, "unknown")
	}
}
