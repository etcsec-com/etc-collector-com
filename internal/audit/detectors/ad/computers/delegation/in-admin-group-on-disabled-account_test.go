package delegation

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestInAdminGroupOnDisabledAccount_DisabledFlagged_ActiveNotFlagged
// partitions the same group membership on Computer.Disabled in both
// directions, mirror image of TestInAdminGroup_DisabledExcluded_ActiveIncluded.
func TestInAdminGroupOnDisabledAccount_DisabledFlagged_ActiveNotFlagged(t *testing.T) {
	dn := "CN=Print Operators,CN=Builtin," + inAdminGroupDomainDN
	sid := "S-1-5-32-550"

	t.Run("disabled computer is flagged", func(t *testing.T) {
		c := types.Computer{DN: "CN=WKSDISABLED," + inAdminGroupDomainDN, MemberOf: []string{dn}, Disabled: true}
		data := &audit.DetectorData{IncludeDetails: true, Computers: []types.Computer{c}, ObjectBySID: groupObject(dn, sid)}
		f := NewInAdminGroupOnDisabledAccountDetector().Detect(context.Background(), data)[0]
		if f.Count != 1 {
			t.Fatalf("disabled computer member must be flagged by the Low detector, got Count=%d, want 1", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("AffectedEntities = %d, want 1", len(f.AffectedEntities))
		}
	})

	t.Run("active computer is not flagged", func(t *testing.T) {
		c := types.Computer{DN: "CN=WKSACTIVE," + inAdminGroupDomainDN, MemberOf: []string{dn}, Disabled: false}
		data := &audit.DetectorData{Computers: []types.Computer{c}, ObjectBySID: groupObject(dn, sid)}
		f := NewInAdminGroupOnDisabledAccountDetector().Detect(context.Background(), data)[0]
		if f.Count != 0 {
			t.Fatalf("active computer member must not be flagged by the Low (disabled-only) detector, got Count=%d, want 0", f.Count)
		}
	})
}

// TestInAdminGroupOnDisabledAccount_HomonymNeverMatches mirrors the Critical
// detector's homonym coverage: a disabled computer in a same-named decoy
// group with an ordinary RID must never be flagged here either.
func TestInAdminGroupOnDisabledAccount_HomonymNeverMatches(t *testing.T) {
	fakeDN := "CN=Backup Operators,CN=Users," + inAdminGroupDomainDN
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-94115"
	c := types.Computer{
		DN:       "CN=WKS01," + inAdminGroupDomainDN,
		MemberOf: []string{fakeDN},
		Disabled: true,
	}
	data := &audit.DetectorData{Computers: []types.Computer{c}, ObjectBySID: groupObject(fakeDN, fakeSID)}
	f := NewInAdminGroupOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("homonym with an ordinary RID must not flag the disabled computer, got Count=%d, want 0", f.Count)
	}
}

// TestInAdminGroupOnDisabledAccount_ExactGroupSet is the same table-driven
// exact-set lock as the Critical detector, applied to disabled computers -
// same domain/Builtin SID split, for the same reason (see the Critical
// detector's TestInAdminGroup_ExactGroupSet doc comment).
func TestInAdminGroupOnDisabledAccount_ExactGroupSet(t *testing.T) {
	inSetDomain := []string{"-512", "-516", "-519", "-527", "-526"}
	inSetBuiltin := []string{"-548", "-544", "-551", "-550", "-549"}
	outOfSet := []struct {
		name   string
		suffix string
	}{
		{"Domain_Users_-513", "-513"},
		{"Domain_Computers_-515", "-515"},
		{"RODC_-521", "-521"},
		{"Replicator_S-1-5-32-552", "S-1-5-32-552"},
		{"neighbor_-1512_no_dash_confusion", "-1512"},
	}

	for _, suffix := range inSetDomain {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users," + inAdminGroupDomainDN
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			c := types.Computer{DN: "CN=WKS" + suffix + "," + inAdminGroupDomainDN, MemberOf: []string{dn}, Disabled: true}
			data := &audit.DetectorData{Computers: []types.Computer{c}, ObjectBySID: groupObject(dn, sid)}
			f := NewInAdminGroupOnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in inAdminGroupSIDSuffixes; disabled membership must be flagged, got Count=%d, want 1", suffix, f.Count)
			}
		})
	}

	for _, suffix := range inSetBuiltin {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Builtin," + inAdminGroupDomainDN
			sid := "S-1-5-32" + suffix
			c := types.Computer{DN: "CN=WKS" + suffix + "," + inAdminGroupDomainDN, MemberOf: []string{dn}, Disabled: true}
			data := &audit.DetectorData{Computers: []types.Computer{c}, ObjectBySID: groupObject(dn, sid)}
			f := NewInAdminGroupOnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in inAdminGroupSIDSuffixes; disabled membership must be flagged, got Count=%d, want 1", suffix, f.Count)
			}
		})
	}

	for _, tc := range outOfSet {
		tc := tc
		t.Run("out_of_set_"+tc.name, func(t *testing.T) {
			var sid string
			if tc.suffix[0] == 'S' {
				sid = tc.suffix
			} else {
				sid = "S-1-5-21-9999999999-8888888888-7777777777" + tc.suffix
			}
			dn := "CN=Group" + tc.name + ",CN=Users," + inAdminGroupDomainDN
			c := types.Computer{DN: "CN=WKS-" + tc.name + "," + inAdminGroupDomainDN, MemberOf: []string{dn}, Disabled: true}
			data := &audit.DetectorData{Computers: []types.Computer{c}, ObjectBySID: groupObject(dn, sid)}
			f := NewInAdminGroupOnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in inAdminGroupSIDSuffixes; disabled membership must not be flagged, got Count=%d, want 0", tc.suffix, f.Count)
			}
		})
	}
}

func TestInAdminGroupOnDisabledAccount_SeverityIsLow(t *testing.T) {
	f := NewInAdminGroupOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{})[0]
	if f.Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityLow)
	}
}

func TestInAdminGroupOnDisabledAccount_DescriptionTextLocked(t *testing.T) {
	want := "Disabled computer account is a direct member of a privileged group protected by AdminSDHolder (Domain Admins, Enterprise Admins, Administrators, Schema Admins, Account/Backup/Print/Server Operators, Key/Enterprise Key Admins, Domain Controllers), matched by SID. It cannot authenticate while disabled, so it cannot exercise the privilege. Membership is not removed by this state - it returns to full effect the instant the account is re-enabled. Remediation: remove the account from the group."
	f := NewInAdminGroupOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{})[0]
	if f.Description != want {
		t.Fatalf("Description changed:\ngot:  %q\nwant: %q", f.Description, want)
	}
}
