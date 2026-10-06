package sspr

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDMethodsWeak       = "SSPR_METHODS_WEAK"
	CategoryMethodsWeak = audit.CategoryIdentity
)

// MethodsWeakDetector checks if SSPR uses weak authentication methods
type MethodsWeakDetector struct {
	audit.BaseDetector
}

// NewSsprMethodsWeakDetector creates a new SSPR weak methods detector
func NewSsprMethodsWeakDetector() *MethodsWeakDetector {
	return &MethodsWeakDetector{
		BaseDetector: audit.NewBaseDetector(IDMethodsWeak, CategoryMethodsWeak),
	}
}

// Detect checks if SSPR uses weak methods (security questions, SMS)
//
// Known limitation (non vu, not fixable in this detector alone): the unified
// authenticationMethodsPolicy this reads only governs SSPR once the tenant's
// migration state is migrationComplete. Microsoft Graph exposes this as
// authenticationMethodsPolicy.policyMigrationState - premigration means
// "the authentication methods policy is used for authentication only, legacy
// policies are respected [for SSPR]"; migrationInProgress still respects the
// legacy SSPR policy too; only migrationComplete means "legacy policies are
// ignored" (Microsoft Graph, authenticationMethodsPolicy resource type,
// learn.microsoft.com/graph/api/resources/authenticationmethodspolicy,
// property table for policyMigrationState). See also Microsoft Learn, "How
// to migrate to the Authentication methods policy"
// (learn.microsoft.com/entra/identity/authentication/how-to-authentication-methods-manage),
// which as of its latest update still documents migration as an
// admin-driven, fully reversible, ongoing process - not something every
// tenant has necessarily completed.
//
// types.AuthMethodsPolicy (pkg/types/azure.go) does not carry
// policyMigrationState, and the Graph call populating it
// (internal/providers/azure/client.go, GetAuthMethodsPolicy) does not
// request it either - both out of this detector's scope. So this
// check reads the unified policy unconditionally: on a tenant still on
// premigration or migrationInProgress, the legacy SSPR policy is the
// authoritative source and this detector's verdict may not reflect it.
func (d *MethodsWeakDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:     IDMethodsWeak,
		Severity: types.SeverityMedium,
		Category: string(CategoryMethodsWeak),
		Title:    "Weak SSPR Authentication Methods",
		Description: "SSPR uses weak methods (security questions, SMS) in the unified Authentication methods policy. Recommend app-based or FIDO2 " +
			"methods. This reads the unified policy directly; on a tenant that has not completed migration to it (policyMigrationState != " +
			"migrationComplete), the legacy SSPR policy governs instead and is not checked here.",
		Count: 0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	// Check if weak methods are enabled but no strong methods
	smsEnabled := data.AzureAuthMethodsPolicy.SMS.State == "enabled"
	emailEnabled := data.AzureAuthMethodsPolicy.Email.State == "enabled"
	authenticatorEnabled := data.AzureAuthMethodsPolicy.MicrosoftAuthenticator.State == "enabled"
	fido2Enabled := data.AzureAuthMethodsPolicy.FIDO2.State == "enabled"

	if (smsEnabled || emailEnabled) && !authenticatorEnabled && !fido2Enabled {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSsprMethodsWeakDetector())
}
