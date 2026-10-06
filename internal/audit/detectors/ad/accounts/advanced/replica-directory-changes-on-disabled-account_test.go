package advanced

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestReplicaDirectoryChangesOnDisabledAccount_BothRights_Counted mirrors
// the active-detector "two separate ACEs" case, but on a disabled account:
// it must fire on THIS detector, not the active one (see
// TestReplicaDirectoryChanges_ActiveDisabledPartition in the sibling file
// for the cross-detector partition check).
func TestReplicaDirectoryChangesOnDisabledAccount_BothRights_Counted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9101"
	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:          []types.User{replicaTestUser("disabled-dcsync", sid, true)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
		},
	}
	findings := NewReplicaDirectoryChangesOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: disabled non-admin user granted both rights", findings[0].Count)
	}
}

// TestReplicaDirectoryChangesOnDisabledAccount_OnlyOneRight_NotCounted
// mirrors the "one right alone" guard for the disabled population.
func TestReplicaDirectoryChangesOnDisabledAccount_OnlyOneRight_NotCounted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9102"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("disabled-partial", sid, true)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
		},
	}
	findings := NewReplicaDirectoryChangesOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: one right alone cannot run DCSync, even disabled", findings[0].Count)
	}
}

// TestReplicaDirectoryChangesOnDisabledAccount_InheritOnlyACE_NamedObjectType_NotCounted
// is the disabled-population mirror of
// TestReplicaDirectoryChanges_InheritOnlyACE_NamedObjectType_NotCounted in
// the sibling file, proving the MB fix (guard must not be narrowed to ACEs
// with an empty ObjectType) holds on the shared replicaRootHolders for both
// keys.
func TestReplicaDirectoryChangesOnDisabledAccount_InheritOnlyACE_NamedObjectType_NotCounted(t *testing.T) {
	sid := "S-1-5-21-1-2-3-9103"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("inherit-only-named-guid-disabled", sid, true)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID, InheritOnly: true},
			{ObjectDN: replicaDomainDN, Trustee: sid, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID, InheritOnly: true},
		},
	}
	findings := NewReplicaDirectoryChangesOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an INHERIT_ONLY ACE naming an extended right GUID directly still does not apply to the root itself (MS-ADTS 3.1)", findings[0].Count)
	}
}

// TestReplicaDirectoryChangesOnDisabledAccount_DomainAdminNotFlagged guards
// the baseline on the disabled path too.
func TestReplicaDirectoryChangesOnDisabledAccount_DomainAdminNotFlagged(t *testing.T) {
	domainAdminSID := "S-1-5-21-1-2-3-512"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users:      []types.User{replicaTestUser("corp-da-disabled", domainAdminSID, true)},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: replicaDomainDN, Trustee: domainAdminSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesGUID},
			{ObjectDN: replicaDomainDN, Trustee: domainAdminSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED", ObjectType: litGetChangesAllGUID},
		},
	}
	findings := NewReplicaDirectoryChangesOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: Domain Admins are an expected baseline holder, even disabled", findings[0].Count)
	}
}

// TestReplicaDirectoryChangesOnDisabledAccount_Severity pins Severity = Low.
func TestReplicaDirectoryChangesOnDisabledAccount_Severity(t *testing.T) {
	findings := NewReplicaDirectoryChangesOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN}})
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want %q", findings[0].Severity, types.SeverityLow)
	}
}

// TestReplicaDirectoryChangesOnDisabledAccount_DescriptionLocked pins the
// exact Description text with a literal comparison.
func TestReplicaDirectoryChangesOnDisabledAccount_DescriptionLocked(t *testing.T) {
	const want = "Disabled accounts hold both the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights - or an equivalent grant (GenericAll, or a CONTROL_ACCESS ACE with no ObjectType, which AD grants as every extended right) - on the domain root (Microsoft Learn, Win32 AD Schema reference, \"DS-Replication-Get-Changes[-All] extended right\"). A disabled account cannot obtain a new ticket-granting ticket ([MS-KILE], \"Check Account Policy for Every TGT Request\", KDC_ERR_CLIENT_REVOKED); however [MS-KILE] does not revoke a ticket-granting ticket already issued before the account was disabled, and when POLICY_KERBEROS_VALIDATE_CLIENT is set, [MS-KILE] 3.3.5.7.1 (\"Check Account Policy for Every Session Ticket Request\") still has the account KDC re-check a ticket-granting ticket older than 20 minutes on every new service-ticket request and reject it once Disabled is true - so the residual window is bounded by the lifetime of service tickets already issued before that 20-minute re-check, not by the ticket-granting ticket's own lifetime. The grant itself is not removed by disabling the account, and it returns to full relevance the instant the account is re-enabled. Holding only one of the two rights cannot perform DCSync and is not reported. Limits: only user accounts are checked - computer accounts and groups holding the rights are not, and group membership is not expanded to the users inside; an ACE flagged inherit-only (applies only to descendants, not the domain root itself) is ignored; and an explicit ACCESS_DENIED ACE elsewhere in the same ACL is not evaluated against a separate grant."
	findings := NewReplicaDirectoryChangesOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN}})
	if findings[0].Description != want {
		t.Fatalf("Description =\n%q\nwant\n%q", findings[0].Description, want)
	}
}
