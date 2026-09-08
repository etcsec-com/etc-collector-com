package advanced

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const replicaDomainDN = "DC=contoso,DC=com"

// TestReplicaDirectoryChanges_ACERightsFlagged pins the fix: the detector
// now reads the actual DS-Replication-Get-Changes[-All] ACE on the domain
// root instead of guessing from a description keyword or a service-like
// name. A non-admin user directly granted both rights must fire.
func TestReplicaDirectoryChanges_ACERightsFlagged(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9001"

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: replicaDomainDN},
		Users: []types.User{
			{SAMAccountName: "aadconnect", ObjectSID: nonAdminSID},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   replicaDomainDN,
				Trustee:    nonAdminSID,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
				ObjectType: types.GUIDDSReplicationGetChanges,
			},
			{
				ObjectDN:   replicaDomainDN,
				Trustee:    nonAdminSID,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
				ObjectType: types.GUIDDSReplicationGetChangesAll,
			},
		},
	}

	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: non-admin user directly granted DCSync rights", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_KeywordAloneNotFlagged pins the removal of
// the old heuristic: an account whose description merely mentions
// "replication" (or a svc-prefixed name with adminCount) but holds no ACE
// at all must not fire - that was the exact source of unfounded findings.
func TestReplicaDirectoryChanges_KeywordAloneNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users: []types.User{
			{
				SAMAccountName: "svc-repl",
				ObjectSID:      "S-1-5-21-1-2-3-9002",
				Description:    "handles directory sync for the reporting tool",
				AdminCount:     true,
			},
		},
	}

	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: no ACE grants replication rights, keyword/name alone must not fire", findings[0].Count)
	}
}

// TestReplicaDirectoryChanges_DomainAdminNotFlagged guards the baseline:
// Domain Admins hold this by default and must not be flagged.
func TestReplicaDirectoryChanges_DomainAdminNotFlagged(t *testing.T) {
	domainAdminSID := "S-1-5-21-1-2-3-512"

	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: replicaDomainDN},
		Users: []types.User{
			{SAMAccountName: "corp-da", ObjectSID: domainAdminSID},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   replicaDomainDN,
				Trustee:    domainAdminSID,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
				ObjectType: types.GUIDDSReplicationGetChanges,
			},
		},
	}

	findings := NewReplicaDirectoryChangesDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: Domain Admins are an expected baseline holder", findings[0].Count)
	}
}
