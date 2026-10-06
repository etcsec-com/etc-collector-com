package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AuthenticatedUsersApplyDetector checks for GPOs that apply to all authenticated users
type AuthenticatedUsersApplyDetector struct {
	audit.BaseDetector
}

// NewAuthenticatedUsersApplyDetector creates a new detector
func NewAuthenticatedUsersApplyDetector() *AuthenticatedUsersApplyDetector {
	return &AuthenticatedUsersApplyDetector{
		BaseDetector: audit.NewBaseDetector("GPO_AUTHENTICATED_USERS_APPLY", audit.CategoryGPO),
	}
}

const (
	sidAuthenticatedUsers = "S-1-5-11"

	// applyGroupPolicyRight is CONTROL_ACCESS (types.MaskControlAccess,
	// 0x00000100) - the bit an extended-right ACE carries. It used to be
	// 0x00010000, which learn.microsoft.com/windows/win32/api/iads/
	// ne-iads-ads_rights_enum documents as ADS_RIGHT_DELETE: this detector
	// and GPO_NO_SECURITY_FILTERING were testing for the right to DELETE the
	// GPO, not to apply it.
	//
	// The bit alone doesn't say WHICH extended right an ACE grants - that
	// needs the ACE's ObjectType GUID, which audit.GPOAcl (shared core,
	// out of scope here) has no field for. client.go's
	// gpoAclFromACLEntry resolves this bit to mean specifically
	// Apply-Group-Policy (edacfd8f-ffb3-11d1-b41d-00a0c968f939,
	// learn.microsoft.com/windows/win32/adschema/r-apply-group-policy)
	// before data.GPOAcls is ever built - see audit.GrantsApplyGroupPolicy.
	applyGroupPolicyRight = types.MaskControlAccess
)

// Detect executes the detection
func (d *AuthenticatedUsersApplyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.GPO

	// Get linked GPO GUIDs
	linkedGuids := make(map[string]bool)
	for _, link := range data.GPOLinks {
		if link.LinkEnabled {
			linkedGuids[strings.ToLower(link.GPOCN)] = true
		}
	}

	for _, gpo := range data.GPOs {
		// Only check linked GPOs
		if !linkedGuids[strings.ToLower(gpo.CN)] {
			continue
		}

		// Get ACLs for this GPO
		for _, acl := range data.GPOAcls {
			if strings.EqualFold(acl.GPODN, gpo.DistinguishedName) {
				if acl.Trustee == sidAuthenticatedUsers && (acl.AccessMask&applyGroupPolicyRight) != 0 {
					affected = append(affected, gpo)
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "GPO Applies to All Authenticated Users",
		Description: "GPOs with Authenticated Users granted the 'Apply Group Policy' permission. This is the default but may be too broad for sensitive policies.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedGPOEntities(affected)
		}
		finding.Details = map[string]interface{}{
			"recommendation": "Review if all GPOs should apply to all users. Consider using security filtering for sensitive policies.",
			"note":           "This is informational - Authenticated Users is the default.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAuthenticatedUsersApplyDetector())
}
