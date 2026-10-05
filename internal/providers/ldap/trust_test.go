package ldap

import "testing"

// TrustType must carry topology (Parent/Child/External/Forest),
// derived from the trustAttributes FOREST_TRANSITIVE bit and a DN comparison,
// not the LDAP trustType attribute (which is the trust PROTOCOL and now lives
// in TrustProtocolType). Before this fix, no code path produced a topology
// value at all, so every detector comparing TrustType against these four
// strings could never match regardless of the trust's real attributes.
func TestTrustTopology(t *testing.T) {
	tests := []struct {
		name          string
		trustAttrs    int
		targetDomain  string
		currentDomain string
		want          string
	}{
		{
			name:          "forest transitive bit set is Forest regardless of DN",
			trustAttrs:    trustAttrForestTransitive,
			targetDomain:  "partner.example",
			currentDomain: "contoso.com",
			want:          "Forest",
		},
		{
			name:          "forest transitive combined with within-forest still Forest",
			trustAttrs:    trustAttrForestTransitive | trustAttrWithinForest,
			targetDomain:  "child.contoso.com",
			currentDomain: "contoso.com",
			want:          "Forest",
		},
		{
			name:          "within forest, target is a subdomain of us is Child",
			trustAttrs:    trustAttrWithinForest,
			targetDomain:  "child.contoso.com",
			currentDomain: "contoso.com",
			want:          "Child",
		},
		{
			name:          "within forest, target is our parent domain is Parent",
			trustAttrs:    trustAttrWithinForest,
			targetDomain:  "contoso.com",
			currentDomain: "child.contoso.com",
			want:          "Parent",
		},
		{
			name:          "within forest, case-insensitive DN comparison",
			trustAttrs:    trustAttrWithinForest,
			targetDomain:  "CHILD.CONTOSO.COM",
			currentDomain: "contoso.com",
			want:          "Child",
		},
		{
			name:          "neither bit set is External",
			trustAttrs:    0,
			targetDomain:  "other.org",
			currentDomain: "contoso.com",
			want:          "External",
		},
		{
			name:          "quarantined + cross-org bits alone do not imply Forest",
			trustAttrs:    trustAttrQuarantinedDomain | trustAttrCrossOrganization,
			targetDomain:  "other.org",
			currentDomain: "contoso.com",
			want:          "External",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trustTopology(tt.trustAttrs, tt.targetDomain, tt.currentDomain)
			if got != tt.want {
				t.Errorf("trustTopology(%#x, %q, %q) = %q, want %q",
					tt.trustAttrs, tt.targetDomain, tt.currentDomain, got, tt.want)
			}
		})
	}
}

// AESEnabled/RC4Enabled must be derived from
// msDS-SupportedEncryptionTypes. Before this fix, the fields were declared on
// Trust and read by ANSSI_R32_TRUST_RC4_ALLOWED but never assigned, so
// AESEnabled was always false and the detector fired on every trust
// unconditionally (!false || RC4Enabled == true, always).
func TestTrustEncryptionFlags(t *testing.T) {
	tests := []struct {
		name     string
		encTypes int
		wantAES  bool
		wantRC4  bool
	}{
		{"unset attribute defaults to AES-disabled", 0, false, false},
		{"AES128 only", trustEncTypeAES128, true, false},
		{"AES256 only", trustEncTypeAES256, true, false},
		{"AES128 and AES256", trustEncTypeAES128 | trustEncTypeAES256, true, false},
		{"RC4 only", trustEncTypeRC4HMAC, false, true},
		{"AES and RC4 both advertised (downgrade still possible)", trustEncTypeAES128 | trustEncTypeRC4HMAC, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aes, rc4 := trustEncryptionFlags(tt.encTypes)
			if aes != tt.wantAES || rc4 != tt.wantRC4 {
				t.Errorf("trustEncryptionFlags(%#x) = (aes=%v, rc4=%v), want (aes=%v, rc4=%v)",
					tt.encTypes, aes, rc4, tt.wantAES, tt.wantRC4)
			}
		})
	}
}
