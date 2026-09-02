package signing

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LdapChannelBindingDisabledDetector detects if LDAP channel binding is disabled
type LdapChannelBindingDisabledDetector struct {
	audit.BaseDetector
}

// NewLdapChannelBindingDisabledDetector creates a new detector
func NewLdapChannelBindingDisabledDetector() *LdapChannelBindingDisabledDetector {
	return &LdapChannelBindingDisabledDetector{
		BaseDetector: audit.NewBaseDetector("LDAP_CHANNEL_BINDING_DISABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LdapChannelBindingDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "LDAP Channel Binding Not Required",
		Description: "LDAP channel binding is not set to 'Always', leaving the domain vulnerable to LDAP relay attacks.",
		Count:       0,
	}

	// Same guard as SMB_SIGNING_DISABLED (T_046/B_049): an empty
	// data.GPOPolicies means SYSVOL was never reached, not "no policy sets
	// this key". The previous fallback below even said so in its own note
	// ("SYSVOL data not available") while still reporting a High finding —
	// it read data.DomainInfo.ChannelBindingRequired, a field nothing in
	// this codebase ever assigns, so it fired unconditionally whenever GPO
	// data was empty, measured or not.
	if len(data.GPOPolicies) == 0 {
		return []types.Finding{finding}
	}

	// Check GPO Registry.pol for LdapEnforceChannelBinding
	cbValue := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.LDAPChannelBinding
	})

	if cbValue != nil {
		// 0=never, 1=when supported, 2=always
		if *cbValue < 2 {
			finding.Count = 1
			finding.Details = map[string]interface{}{
				"currentValue":    *cbValue,
				"currentSetting":  channelBindingLabel(*cbValue),
				"requiredValue":   2,
				"requiredSetting": "Always",
				"recommendation":  "Set 'Domain controller: LDAP server channel binding token requirements' to 'Always'.",
			}
		}
	} else {
		// Measured (SYSVOL reachable) but no policy sets this key anywhere —
		// Windows default (not required) genuinely applies.
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"note":           "SYSVOL was reachable but no GPO configures LDAP channel binding. Windows defaults do not require it.",
			"recommendation": "Set 'Domain controller: LDAP server channel binding token requirements' to 'Always'.",
		}
	}

	return []types.Finding{finding}
}

func channelBindingLabel(v int) string {
	switch v {
	case 0:
		return "Never"
	case 1:
		return "When Supported"
	case 2:
		return "Always"
	default:
		return fmt.Sprintf("Unknown (%d)", v)
	}
}

func init() {
	audit.MustRegister(NewLdapChannelBindingDisabledDetector())
}
