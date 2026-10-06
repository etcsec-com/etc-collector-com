package cis

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestUserRights_ExcessiveAdminGroupMembership_NoLongerFlagged:
// the detector used to flag domains with many Domain/Enterprise/Schema Admins
// against unsourced thresholds (5/2/1) - not a CIS 2.2.x User Rights
// Assignment check at all. Group membership counts, with no PrivilegeRights
// data present, must no longer produce a finding here (that concern belongs
// to other, dedicated privileged-group detectors).
func TestUserRights_ExcessiveAdminGroupMembership_NoLongerFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 (no PrivilegeRights data collected)", findings)
	}
}

// TestUserRights_ActAsPartOfOS_Flagged: CIS 2.2.4 requires "Act
// as part of the operating system" (SeTcbPrivilege) to be granted to no one.
// This real User Rights Assignment signal was previously ignored entirely.
func TestUserRights_ActAsPartOfOS_Flagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {PrivilegeRights: &audit.PrivilegeRights{
			SeTcbPrivilege: []string{"S-1-5-21-1-2-3-1105"},
		}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (SeTcbPrivilege granted to a non-empty SID list)", findings)
	}
}

// TestUserRights_DelegationTrust_Flagged: CIS 2.2.29 requires
// "Enable computer and user accounts to be trusted for delegation"
// (SeEnableDelegationPrivilege) to be granted to no one - unconstrained
// delegation is a well-known AD privilege-escalation vector.
func TestUserRights_DelegationTrust_Flagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {PrivilegeRights: &audit.PrivilegeRights{
			SeEnableDelegationPrivilege: []string{"S-1-5-21-1-2-3-1105"},
		}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (SeEnableDelegationPrivilege granted to a non-empty SID list)", findings)
	}
}

// TestUserRights_BothEmpty_NoFinding is the regression check for the
// compliant "No One" state on both rights.
func TestUserRights_BothEmpty_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {PrivilegeRights: &audit.PrivilegeRights{}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0", findings)
	}
}
