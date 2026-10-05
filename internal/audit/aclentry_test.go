package audit

import (
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

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

// GPO_AUTHENTICATED_USERS_APPLY and GPO_NO_SECURITY_FILTERING tested
// AccessMask&0x00010000 (ADS_RIGHT_DELETE) believing it was Apply-Group-Policy,
// a CONTROL_ACCESS extended right identified by ObjectType GUID
// edacfd8f-ffb3-11d1-b41d-00a0c968f939, never by a bit of the access mask.
// The first case here is the red->green proof: it fails against the old
// 0x00010000 predicate (a DELETE-only ACE would incorrectly grant) and
// passes against GrantsApplyGroupPolicy.
func TestGrantsApplyGroupPolicy(t *testing.T) {
	const (
		deleteRight   = 0x00010000 // ADS_RIGHT_DELETE - NOT Apply-Group-Policy
		controlAccess = 0x00000100 // CONTROL_ACCESS - extended right marker
		writeProperty = 0x00000020
	)

	cases := []struct {
		name       string
		mask       int
		objectType string
		want       bool
	}{
		{"DELETE alone does not grant Apply-Group-Policy", deleteRight, "", false},
		{"CONTROL_ACCESS + Apply-Group-Policy GUID grants it", controlAccess, guidApplyGroupPolicy, true},
		{"CONTROL_ACCESS + empty ObjectType grants every extended right", controlAccess, "", true},
		{"WriteProperty + the same GUID does not grant it (wrong access type)", writeProperty, guidApplyGroupPolicy, false},
		{"CONTROL_ACCESS + a different extended right's GUID does not grant it", controlAccess, guidDSReplicationGetChanges, false},
		{"CONTROL_ACCESS + Apply-Group-Policy GUID, case-insensitive", controlAccess, strings.ToUpper(guidApplyGroupPolicy), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := GrantsApplyGroupPolicy(tc.mask, tc.objectType); got != tc.want {
				t.Errorf("GrantsApplyGroupPolicy(0x%x, %q) = %v, want %v", tc.mask, tc.objectType, got, tc.want)
			}
		})
	}
}

// GPO.HasWeakACL is declared and read by ANSSI_R59_TIER0_OU_POLICIES
// and ATTACK_PATH_GPO_TO_DA but never assigned by the collector, so neither
// detector could ever fire on this condition regardless of the real ACL - a
// false HasWeakACL always reads as "no problem" though the field was never
// computed. Fixed by computing the same dangerousMask convention already used
// by schema-permissions.go / dpapi-key-acl.go / admin-sd-holder-modified.go,
// inline from data.GPOAcls (WeakACLGPODNs) rather than via a precomputed
// struct field, since populating a shared field between collection and
// detection needs an engine.go change out of scope here.
func TestWeakACLGPODNs(t *testing.T) {
	domainSID := "S-1-5-21-1111111111-2222222222-3333333333"
	nonAdminSID := "S-1-5-21-1111111111-2222222222-3333333333-9999"
	domainAdminsSID := domainSID + "-512" // privileged, must be excluded

	data := &DetectorData{
		DomainInfo: &types.DomainInfo{DomainSID: domainSID},
		GPOAcls: []GPOAcl{
			// Non-admin GenericAll grant - weak.
			{GPODN: "CN={weak},CN=Policies,CN=System,DC=contoso,DC=com", Trustee: nonAdminSID, AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
			// Domain Admins GenericAll grant - expected, not weak.
			{GPODN: "CN={admin-only},CN=Policies,CN=System,DC=contoso,DC=com", Trustee: domainAdminsSID, AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
			// Non-admin read-only grant - not a dangerous right.
			{GPODN: "CN={read-only},CN=Policies,CN=System,DC=contoso,DC=com", Trustee: nonAdminSID, AccessMask: types.MaskReadProperty, AceType: "ACCESS_ALLOWED"},
			// Non-admin GenericAll but as a DENY ace - not a grant.
			{GPODN: "CN={deny-only},CN=Policies,CN=System,DC=contoso,DC=com", Trustee: nonAdminSID, AccessMask: types.MaskGenericAll, AceType: "ACCESS_DENIED"},
		},
	}

	weak := WeakACLGPODNs(data)

	if !weak["cn={weak},cn=policies,cn=system,dc=contoso,dc=com"] {
		t.Error("GPO with non-admin GenericAll grant should be weak")
	}
	if weak["cn={admin-only},cn=policies,cn=system,dc=contoso,dc=com"] {
		t.Error("GPO where only Domain Admins hold GenericAll should not be weak (privileged trustee excluded)")
	}
	if weak["cn={read-only},cn=policies,cn=system,dc=contoso,dc=com"] {
		t.Error("GPO where a non-admin holds only ReadProperty should not be weak (not in dangerousMask)")
	}
	if weak["cn={deny-only},cn=policies,cn=system,dc=contoso,dc=com"] {
		t.Error("GPO where the dangerous mask only appears on a DENY ace should not be weak")
	}
	if weak["cn={clean},cn=policies,cn=system,dc=contoso,dc=com"] {
		t.Error("GPO with no ACEs at all should not be weak")
	}
	if len(weak) != 1 {
		t.Errorf("expected exactly 1 weak GPO, got %d: %v", len(weak), weak)
	}
}

// CertAuthority.HasWeakACL is declared and read by
// ANSSI_R36_CA_RISKS but never assigned by the collector: CA DNs were never
// in collectData's objectDNs batch, so no CA ever had ACEs in
// data.ACLEntries and the branch could never fire regardless of the real
// ACL. Fixed by adding CA DNs to that batch (internal/audit/engine.go,
// shared core) and computing the same dangerousMask
// convention inline from data.ACLEntries (WeakACLCADNs), mirroring
// WeakACLGPODNs above rather than mutating a shared struct field from a
// detector.
func TestWeakACLCADNs(t *testing.T) {
	domainSID := "S-1-5-21-1111111111-2222222222-3333333333"
	nonAdminSID := "S-1-5-21-1111111111-2222222222-3333333333-9999"
	domainAdminsSID := domainSID + "-512" // privileged, must be excluded

	weakCADN := "CN=weak-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com"
	adminOnlyCADN := "CN=admin-only-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com"
	readOnlyCADN := "CN=read-only-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com"
	denyOnlyCADN := "CN=deny-only-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com"
	cleanCADN := "CN=clean-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com"
	notACADN := "CN=some-user,DC=contoso,DC=com" // has a weak ACE but isn't a CA - must not leak in

	data := &DetectorData{
		DomainInfo: &types.DomainInfo{DomainSID: domainSID},
		CertAuthorities: []types.CertAuthority{
			{DN: weakCADN, Name: "weak-CA"},
			{DN: adminOnlyCADN, Name: "admin-only-CA"},
			{DN: readOnlyCADN, Name: "read-only-CA"},
			{DN: denyOnlyCADN, Name: "deny-only-CA"},
			{DN: cleanCADN, Name: "clean-CA"},
		},
		ACLEntries: []types.ACLEntry{
			// Non-admin GenericAll grant - weak.
			{ObjectDN: weakCADN, Trustee: nonAdminSID, AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
			// Domain Admins GenericAll grant - expected, not weak.
			{ObjectDN: adminOnlyCADN, Trustee: domainAdminsSID, AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
			// Non-admin read-only grant - not a dangerous right.
			{ObjectDN: readOnlyCADN, Trustee: nonAdminSID, AccessMask: types.MaskReadProperty, AceType: "ACCESS_ALLOWED"},
			// Non-admin GenericAll but as a DENY ace - not a grant.
			{ObjectDN: denyOnlyCADN, Trustee: nonAdminSID, AccessMask: types.MaskGenericAll, AceType: "ACCESS_DENIED"},
			// Weak grant on a non-CA object - must be filtered out by the CA DN set.
			{ObjectDN: notACADN, Trustee: nonAdminSID, AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	weak := WeakACLCADNs(data)

	if !weak[strings.ToLower(weakCADN)] {
		t.Error("CA with non-admin GenericAll grant should be weak")
	}
	if weak[strings.ToLower(adminOnlyCADN)] {
		t.Error("CA where only Domain Admins hold GenericAll should not be weak (privileged trustee excluded)")
	}
	if weak[strings.ToLower(readOnlyCADN)] {
		t.Error("CA where a non-admin holds only ReadProperty should not be weak (not in dangerousMask)")
	}
	if weak[strings.ToLower(denyOnlyCADN)] {
		t.Error("CA where the dangerous mask only appears on a DENY ace should not be weak")
	}
	if weak[strings.ToLower(cleanCADN)] {
		t.Error("CA with no ACEs at all should not be weak")
	}
	if weak[strings.ToLower(notACADN)] {
		t.Error("a weak grant on a non-CA object must not leak into the CA set")
	}
	if len(weak) != 1 {
		t.Errorf("expected exactly 1 weak CA, got %d: %v", len(weak), weak)
	}
}
