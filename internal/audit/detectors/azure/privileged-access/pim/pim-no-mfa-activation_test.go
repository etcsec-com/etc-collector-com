package pim

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestPIMNoMFAOnActivation_ActiveTimeLimitedAssignmentDoesNotCount covers the
// source review finding: the detector used !ra.IsPermanent as a proxy for
// "PIM-eligible", but a time-limited ACTIVE assignment (IsPermanent=false,
// IsEligible=false) is not eligible - it never goes through PIM activation,
// so there is no "MFA on activation" setting for it to be missing. The sibling
// detectors (PIMLongActivationDetector, PIMNoApprovalRequiredDetector) both
// use ra.IsEligible for this same test; this detector should too.
func TestPIMNoMFAOnActivation_ActiveTimeLimitedAssignmentDoesNotCount(t *testing.T) {
	d := NewPIMNoMFAOnActivationDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{PrincipalID: "p1", RoleID: types.AzureRoleGlobalAdmin, IsPermanent: false, IsEligible: false},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0: a non-permanent, non-eligible (time-limited active) assignment never activates, got %d", f.Count)
	}
}

func TestPIMNoMFAOnActivation_EligibleAssignmentCounts(t *testing.T) {
	d := NewPIMNoMFAOnActivationDetector()
	data := &audit.DetectorData{
		AzureRoleAssignments: []types.RoleAssignment{
			{PrincipalID: "p1", RoleID: types.AzureRoleGlobalAdmin, IsPermanent: false, IsEligible: true},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 for an eligible assignment, got %d", f.Count)
	}
}

func TestPIMNoMFAOnActivation_NoAssignmentsAtAll(t *testing.T) {
	d := NewPIMNoMFAOnActivationDetector()
	f := d.Detect(context.Background(), &audit.DetectorData{})[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 with no role assignments, got %d", f.Count)
	}
}
