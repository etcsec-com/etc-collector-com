package sspr

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNotRequiredAdmins       = "SSPR_NOT_REQUIRED_ADMINS"
	CategoryNotRequiredAdmins = audit.CategoryIdentity
)

// NotRequiredAdminsDetector checks if SSPR is required for administrators
type NotRequiredAdminsDetector struct {
	audit.BaseDetector
}

// NewSsprNotRequiredAdminsDetector creates a new SSPR not required for admins detector
func NewSsprNotRequiredAdminsDetector() *NotRequiredAdminsDetector {
	return &NotRequiredAdminsDetector{
		BaseDetector: audit.NewBaseDetector(IDNotRequiredAdmins, CategoryNotRequiredAdmins),
	}
}

// Detect checks if admins are subject to SSPR policy
func (d *NotRequiredAdminsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDNotRequiredAdmins,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryNotRequiredAdmins),
		Title:       "SSPR Not Required for Administrators",
		Description: "Some administrator accounts have never registered a self-service password reset method, so they cannot use SSPR even though Microsoft enables and enforces it for admins by default.",
		Count:       0,
	}

	// Source: "Self-service password reset policies" - administrator reset
	// policy differences (learn.microsoft.com/en-us/entra/identity/
	// authentication/concept-sspr-policy#administrator-reset-policy-
	// differences): "By default, administrator accounts are enabled for
	// self-service password reset, and a strong default two-gate password
	// reset policy is enforced. This policy ... can't be changed." Microsoft
	// does expose one tenant-level admin-SSPR policy: authorizationPolicy.
	// allowedToUseSSPR, a single on/off switch ("You can disable the use of
	// SSPR for administrator accounts by setting ... AllowedToUseSspr ...
	// to false") - this codebase does not currently collect that field (it
	// would require a change to the Azure client/engine, outside this
	// detector's ownership), so it cannot be checked here.
	//
	// Because that switch is binary and, when true, already forces the
	// strongest available policy onto every admin, it can't express a
	// per-admin gap. AdminUsers.SSPRRegistered (authmethods.go), aggregated
	// from the same per-user userRegistrationDetails collection already used
	// for MFA, measures a distinct and still-real signal instead: how many
	// admin accounts have never actually registered an SSPR method, i.e.
	// cannot use self-service reset even though the tenant permits it.
	if data.AzureAuthMethodsDetail != nil && data.AzureAuthMethodsDetail.UserRegistrationStats != nil {
		admins := data.AzureAuthMethodsDetail.UserRegistrationStats.AdminUsers
		if gap := admins.Total - admins.SSPRRegistered; gap > 0 {
			finding.Count = gap
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSsprNotRequiredAdminsDetector())
}
