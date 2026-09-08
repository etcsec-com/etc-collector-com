package ldap

import "github.com/etcsec-com/etc-collector/pkg/types"

// applyDNSZoneProperties parses the dNSProperty binary blobs of an
// AD-integrated DNS zone and fills in the fields GetDNSZones exposes.
//
// [MS-DNSP] 2.3.2.1 "dnsProperty" lays out the structure as five DWORDs
// followed by variable-length data and name:
//
//	DataLength(0-3)  NameLength(4-7)  Flag(8-11)  Version(12-15)  Id(16-19)  Data(20+)  Name
//
// The property Id must be read from byte 16, not bytes 4-7 - those are
// NameLength, always 0 for a zone-level property since these properties
// carry no name. Reading the wrong offset means `case 0x00000002`
// (DSPROPERTY_ZONE_ALLOW_UPDATE) can never match and DynamicUpdate stays at
// its "unknown" default for every zone, insecure or not. Verified against a
// live capture from a domain controller (2026-09-08): the ALLOW_UPDATE property is
// `AQAAAAAAAAAAAAAAAQAAAAIAAAABAAAAAA==` - DataLength=1, NameLength=0,
// Flag=0, Version=1, Id=2 at byte 16, Data=0x01 at byte 20 - decoding to
// updateFlag=1 ("nonsecure"), matching the zone's real
// NonsecureAndSecure configuration (docs/security-validation/results/
// t163-manual/VERDICT-T163.md).
func applyDNSZoneProperties(zone *types.DNSZone, dnsProps [][]byte) {
	for _, prop := range dnsProps {
		if len(prop) < 24 {
			continue
		}
		propID := uint32(prop[16]) | uint32(prop[17])<<8 | uint32(prop[18])<<16 | uint32(prop[19])<<24

		switch propID {
		case 0x00000002: // DSPROPERTY_ZONE_ALLOW_UPDATE ([MS-DNSP] 2.2.5.2.4.1 DNS_ZONE_UPDATE)
			updateFlag := uint32(prop[20]) | uint32(prop[21])<<8
			switch updateFlag {
			case 0: // ZONE_UPDATE_OFF
				zone.DynamicUpdate = "none"
			case 1: // ZONE_UPDATE_UNSECURE
				zone.DynamicUpdate = "nonsecure"
			case 2: // ZONE_UPDATE_SECURE
				zone.DynamicUpdate = "secure"
			}
			// A retired DNSSEC-enabled check once read 0x00000010 as a DNSSEC
			// signal, but it is DSPROPERTY_ZONE_NOREFRESH_INTERVAL -
			// dNSProperty carries no DNSSEC state at all; that lives in
			// separate msDNS-SigningKeyDescriptor child objects this query
			// never requests. zone.DNSSECEnabled is intentionally left
			// unassigned (see pkg/types/dns.go) until that data is collected.
		}
	}
}
