package types

// DNSZone represents an AD-integrated DNS zone queried via LDAP
type DNSZone struct {
	DN                string   `json:"dn,omitempty"` // Distinguished Name of the zone object
	Name              string   `json:"name"`
	DynamicUpdate     string   `json:"dynamicUpdate"` // "none", "secure", "nonsecure"
	DNSSECEnabled     bool     `json:"dnssecEnabled"`
	WildcardRecords   []string `json:"wildcardRecords,omitempty"`
	ZoneTransferAllow string   `json:"zoneTransferAllow,omitempty"` // from dNSProperty
}
