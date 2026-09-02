package signing

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LdapSigningDisabledDetector detects if LDAP signing is disabled
type LdapSigningDisabledDetector struct {
	audit.BaseDetector
}

// NewLdapSigningDisabledDetector creates a new detector
func NewLdapSigningDisabledDetector() *LdapSigningDisabledDetector {
	return &LdapSigningDisabledDetector{
		BaseDetector: audit.NewBaseDetector("LDAP_SIGNING_DISABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LdapSigningDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "LDAP Signing Not Required",
		Description: "LDAP signing is not required on domain controllers, making the environment vulnerable to LDAP relay attacks.",
		Count:       0,
	}

	// Same guard as SMB_SIGNING_DISABLED (T_046/B_049): an empty
	// data.GPOPolicies means SYSVOL was never reached, not "no policy sets
	// this key". The previous fallback below read data.DomainInfo.
	// LDAPSigningRequired, a field nothing in this codebase ever assigns —
	// it was permanently false, so the fallback fired unconditionally
	// whenever GPO data was empty, measured or not.
	if len(data.GPOPolicies) == 0 {
		return []types.Finding{finding}
	}

	// Check GPO Registry.pol for LDAPServerIntegrity
	ldapIntegrity := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.LDAPServerIntegrity
	})

	if ldapIntegrity != nil {
		// 0=none, 1=negotiate, 2=require
		if *ldapIntegrity < 2 {
			finding.Count = 1
			finding.Details = map[string]interface{}{
				"currentValue":   *ldapIntegrity,
				"requiredValue":  2,
				"recommendation": "Set 'Domain controller: LDAP server signing requirements' to 'Require signing'.",
			}
		}
	} else {
		// Measured (SYSVOL reachable) but no policy sets this key anywhere —
		// Windows default (not required) genuinely applies.
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"note":           "SYSVOL was reachable but no GPO configures LDAP signing. Windows defaults do not require LDAP signing.",
			"recommendation": "Configure 'Domain controller: LDAP server signing requirements' to 'Require signing' via Group Policy.",
		}
	}

	if data.IncludeDetails && finding.Count > 0 && data.DomainInfo != nil {
		finding.AffectedEntities = []types.AffectedEntity{types.DomainInfoToAffectedEntity(data.DomainInfo)}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLdapSigningDisabledDetector())
}
