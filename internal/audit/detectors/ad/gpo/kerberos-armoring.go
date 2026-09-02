package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberosArmoringDCDetector checks if Kerberos armoring (FAST) is not enforced on DCs
type KerberosArmoringDCDetector struct {
	audit.BaseDetector
}

func NewKerberosArmoringDCDetector() *KerberosArmoringDCDetector {
	return &KerberosArmoringDCDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROS_ARMORING_DC_DISABLED", audit.CategoryGPO),
	}
}

func (d *KerberosArmoringDCDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Kerberos Armoring (FAST) Not Enforced on DCs",
		Description: "Kerberos Flexible Authentication Secure Tunneling (FAST/Armoring) is not configured on Domain Controllers. FAST protects Kerberos pre-authentication exchanges from offline brute-force and AS-REP roasting attacks.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.KerberosArmoringDC
	})

	if v == nil {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Configure KDC support for claims, compound authentication, and Kerberos armoring via GPO.",
		}
	}

	return []types.Finding{finding}
}

// KerberosArmoringClientDetector checks if Kerberos armoring (FAST) is not required on clients
type KerberosArmoringClientDetector struct {
	audit.BaseDetector
}

func NewKerberosArmoringClientDetector() *KerberosArmoringClientDetector {
	return &KerberosArmoringClientDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROS_ARMORING_CLIENT_DISABLED", audit.CategoryGPO),
	}
}

func (d *KerberosArmoringClientDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Kerberos Armoring (FAST) Not Required on Clients",
		Description: "Kerberos FAST armoring is not required on client machines. Without client-side enforcement, pre-authentication exchanges remain vulnerable to interception and offline attacks.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.KerberosArmoringClient
	})

	if v == nil || *v != 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Set Kerberos client support for claims, compound authentication, and armoring to 'Always provide claims' via GPO.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewKerberosArmoringDCDetector())
	audit.MustRegister(NewKerberosArmoringClientDetector())
}
