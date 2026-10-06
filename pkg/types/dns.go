package types

// DNSZone represents an AD-integrated DNS zone queried via LDAP
type DNSZone struct {
	DN            string `json:"dn,omitempty"` // Distinguished Name of the zone object
	Name          string `json:"name"`
	DynamicUpdate string `json:"dynamicUpdate"` // "none", "secure", "nonsecure"
	// DNSSECEnabled is NOT populated by any current provider (see
	// internal/providers/ldap/client.go GetDNSZones): dNSProperty carries no
	// DNSSEC signing signal. Kept as a typed placeholder for when real
	// signing state (msDNS-SigningKeyDescriptor child objects) is collected.
	DNSSECEnabled     bool     `json:"dnssecEnabled"`
	WildcardRecords   []string `json:"wildcardRecords,omitempty"`
	ZoneTransferAllow string   `json:"zoneTransferAllow,omitempty"` // from dNSProperty
}
