package audit

import "testing"

func TestAccessMaskToRight(t *testing.T) {
	cases := []struct {
		name       string
		mask       int
		objectType string
		want       string
	}{
		{"GenericAll", 0x10000000, "", "GenericAll"},
		{"WriteDACL", 0x00040000, "", "WriteDACL"},
		{"WriteOwner", 0x00080000, "", "WriteOwner"},
		{"GenericWrite", 0x40000000, "", "GenericWrite"},
		{"AllExtendedRights without GUID", 0x00000100, "", "AllExtendedRights"},
		{"WriteProperty without GUID", 0x00000020, "", "WriteProperty"},
		{"DCSync (Get-Changes)", 0x00000100, guidDSReplicationGetChanges, "DS-Replication-Get-Changes"},
		{"DCSync (Get-Changes-All)", 0x00000100, guidDSReplicationGetChangesAll, "DS-Replication-Get-Changes-All"},
		{"User-Force-Change-Password", 0x00000100, guidUserForceChangePassword, "User-Force-Change-Password"},
		{"WriteSPN", 0x00000100, guidWriteSPN, "WriteSPN"},
		{"Self-Membership", 0x00000100, guidSelfMembership, "Self-Membership"},
		{"WriteProperty with unknown GUID", 0x00000020, "deadbeef-aaaa-bbbb-cccc-000000000000", "WriteProperty:deadbeef-aaaa-bbbb-cccc-000000000000"},
		// Most-specific wins when bits combine
		{"GenericAll dominates WriteDACL", 0x10000000 | 0x00040000, "", "GenericAll"},
		{"WriteDACL dominates GenericWrite", 0x00040000 | 0x40000000, "", "WriteDACL"},
		// Unrecognised
		{"empty mask, no GUID", 0, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AccessMaskToRight(tc.mask, tc.objectType); got != tc.want {
				t.Errorf("AccessMaskToRight(0x%x, %q) = %q, want %q", tc.mask, tc.objectType, got, tc.want)
			}
		})
	}
}
