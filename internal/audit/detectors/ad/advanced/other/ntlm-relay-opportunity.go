package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NtlmRelayOpportunityDetector detects NTLM relay opportunities
type NtlmRelayOpportunityDetector struct {
	audit.BaseDetector
}

// NewNtlmRelayOpportunityDetector creates a new detector
func NewNtlmRelayOpportunityDetector() *NtlmRelayOpportunityDetector {
	return &NtlmRelayOpportunityDetector{
		BaseDetector: audit.NewBaseDetector("NTLM_RELAY_OPPORTUNITY", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *NtlmRelayOpportunityDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "NTLM Relay Opportunity",
		Description: "LDAP signing or channel binding not enforced. Enables NTLM relay attacks.",
		Count:       0,
	}

	// This used to read data.DomainInfo.LDAPSigningRequired /
	// .ChannelBindingRequired — two fields nothing in this codebase ever
	// assigns (permanently false). isVulnerable was therefore always true:
	// this detector fired on EVERY audit, unconditionally (T_046/B_049).
	// Measure the same GPO registry keys LDAP_SIGNING_DISABLED /
	// LDAP_CHANNEL_BINDING_DISABLED already do, with the same "SYSVOL
	// unreachable = not measured, don't fire" guard.
	if data.DomainInfo == nil || len(data.GPOPolicies) == 0 {
		return []types.Finding{finding}
	}

	ldapIntegrity := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.LDAPServerIntegrity
	})
	cbValue := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.LDAPChannelBinding
	})

	// 0=none/never, 1=negotiate/when-supported, 2=require/always — matches
	// the sibling detectors' thresholds exactly.
	ldapSigningRequired := ldapIntegrity != nil && *ldapIntegrity >= 2
	channelBindingRequired := cbValue != nil && *cbValue >= 2

	if !ldapSigningRequired || !channelBindingRequired {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{types.DomainInfoToAffectedEntity(data.DomainInfo)}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNtlmRelayOpportunityDetector())
}
