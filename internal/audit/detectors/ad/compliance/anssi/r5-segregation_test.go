package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR5Segregation_BackupOperatorsSpecialPrincipal covers the fact that Backup
// Operators is a domain-local Builtin group, so Everyone/Authenticated Users
// can be a member of it without that membership ever appearing in any real
// user's memberOf (Windows computes it at logon time, it never writes a
// per-user back-link). A user with exactly one OTHER privileged-group
// membership must now also be flagged once Backup Operators is open to
// everyone - before the fix, that case was structurally invisible no matter
// the real state of the domain.
func TestR5Segregation_BackupOperatorsSpecialPrincipal(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	user := types.User{
		SAMAccountName: "svc.one",
		Disabled:       false, // enabled
		MemberOf:       []string{"CN=Account Operators,CN=Builtin," + domainDN},
	}

	tests := []struct {
		name          string
		groups        []types.Group
		wantFindCount int
	}{
		{
			name:          "no group data at all - one privileged group only, not flagged",
			groups:        nil,
			wantFindCount: 0,
		},
		{
			name: "Backup Operators has NO special principal member - still not flagged",
			groups: []types.Group{
				{SAMAccountName: "Backup Operators", Members: []string{"CN=some.other.user," + domainDN}},
			},
			wantFindCount: 0,
		},
		{
			name: "Backup Operators open to Everyone (S-1-1-0) - now flagged",
			groups: []types.Group{
				{SAMAccountName: "Backup Operators", Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals," + domainDN}},
			},
			wantFindCount: 1,
		},
		{
			name: "Backup Operators open to Authenticated Users (S-1-5-11) - now flagged",
			groups: []types.Group{
				{SAMAccountName: "Backup Operators", Members: []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals," + domainDN}},
			},
			wantFindCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users:  []types.User{user},
				Groups: tt.groups,
			}
			findings := NewR5SegregationDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			if findings[0].Count != tt.wantFindCount {
				t.Errorf("Count = %d, want %d", findings[0].Count, tt.wantFindCount)
			}
		})
	}
}

// TestR5Segregation_AdminCountAloneNotFlagged: a prior second
// check flagged any user with AdminCount=true and no SPN as a "standard user
// with admin privileges" once more than 20 such users existed. That check
// was internally contradictory - adminSDHolder sets AdminCount=true
// precisely because an account IS/WAS privileged (PA-099 p.40 footnote 16),
// never because it is a standard user - and had no ANSSI source for the >20
// threshold, so it was removed. Before the fix, 21 enabled AdminCount users
// with a single, non-overlapping privileged-group membership each produced
// Count=1 via that check alone; after the fix it must produce Count=0.
func TestR5Segregation_AdminCountAloneNotFlagged(t *testing.T) {
	var users []types.User
	for i := 0; i < 21; i++ {
		users = append(users, types.User{
			SAMAccountName: "priv.user",
			Disabled:       false,
			AdminCount:     true,
			MemberOf:       []string{"CN=Domain Admins,CN=Users,DC=example,DC=com"},
		})
	}

	data := &audit.DetectorData{Users: users}
	findings := NewR5SegregationDetector().Detect(context.Background(), data)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 (AdminCount alone must not be flagged as a standard-user violation)", findings[0].Count)
	}
}
