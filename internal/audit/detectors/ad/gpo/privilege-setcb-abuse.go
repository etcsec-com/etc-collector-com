package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SeTcbAbuseDetector checks if SeTcbPrivilege (Act as OS) is assigned
type SeTcbAbuseDetector struct {
	audit.BaseDetector
}

func NewSeTcbAbuseDetector() *SeTcbAbuseDetector {
	return &SeTcbAbuseDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGE_SETCB_ABUSE", audit.CategoryGPO),
	}
}

func (d *SeTcbAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "SeTcbPrivilege (Act as Part of OS) Assigned",
		Description: "The SeTcbPrivilege (Act as part of the operating system) user right is assigned to user accounts. This privilege allows impersonating any user without authentication, equivalent to being SYSTEM. No user account should have this privilege.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeTcbPrivilege
	})

	// Source: Microsoft Learn "Act as part of the operating system" security
	// policy setting reference. Default value on every server/workstation
	// type is "Not defined" (no group holds it by default, not even
	// Administrators). Best practice: "Don't assign this right to any user
	// accounts... it shouldn't even be assigned to the Administrators group
	// under typical circumstances. When a service requires this user right,
	// configure the service to sign in with the Local System account, which
	// inherently includes this privilege." So SYSTEM (S-1-5-18) is the only
	// safe holder; any other SID - Administrators included - is a flag.
	var unsafe []string
	for _, sid := range sids {
		if sid != "S-1-5-18" { // Only SYSTEM is OK
			unsafe = append(unsafe, sid)
		}
	}

	finding.Count = len(unsafe)
	if len(unsafe) > 0 {
		finding.Details = map[string]interface{}{
			"unsafeSIDs":     unsafe,
			"recommendation": "Remove SeTcbPrivilege from all accounts. Only the SYSTEM account should have this privilege.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSeTcbAbuseDetector())
}
