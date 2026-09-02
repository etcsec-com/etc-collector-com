package industry

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// MFANotEnforcedDetector checks for MFA enforcement on privileged accounts
type MFANotEnforcedDetector struct {
	audit.BaseDetector
}

// NewMFANotEnforcedDetector creates a new detector
func NewMFANotEnforcedDetector() *MFANotEnforcedDetector {
	return &MFANotEnforcedDetector{
		BaseDetector: audit.NewBaseDetector("MFA_NOT_ENFORCED", audit.CategoryCompliance),
	}
}

// UAC flag for smartcard required
const uacSmartcardRequired = 0x40000

// Detect executes the detection
func (d *MFANotEnforcedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Check for privileged accounts without smartcard requirement
	var adminsWithoutMFAList []types.User
	totalAdmins := 0

	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}

		isAdmin := false
		for _, memberOf := range u.MemberOf {
			memberOfLower := strings.ToLower(memberOf)
			if strings.Contains(memberOfLower, "domain admins") ||
				strings.Contains(memberOfLower, "enterprise admins") ||
				strings.Contains(memberOfLower, "schema admins") {
				isAdmin = true
				break
			}
		}

		if isAdmin {
			totalAdmins++
			smartcardRequired := (u.UserAccountControl & uacSmartcardRequired) != 0
			if !smartcardRequired {
				adminsWithoutMFAList = append(adminsWithoutMFAList, u)
			}
		}
	}

	adminsWithoutMFA := len(adminsWithoutMFAList)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "MFA Not Enforced for Privileged Accounts",
		Description: "Multi-factor authentication is not enforced for all privileged accounts. Smartcard requirement should be enabled for admin accounts.",
		Count:       0,
		Details: map[string]interface{}{
			"category":         "Industry Best Practices",
			"totalAdmins":      totalAdmins,
			"adminsWithoutMFA": adminsWithoutMFA,
		},
	}

	if adminsWithoutMFA > 0 {
		finding.Count = adminsWithoutMFA
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities(adminsWithoutMFAList)
		}
		finding.Details["recommendations"] = []string{
			"Enable 'Smart card is required for interactive logon' for all admin accounts",
			"Implement Azure AD Conditional Access with MFA for cloud-integrated environments",
			"Use Windows Hello for Business as an alternative MFA method",
			"Consider third-party MFA solutions for comprehensive coverage",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMFANotEnforcedDetector())
}
