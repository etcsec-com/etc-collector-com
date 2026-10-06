package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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
			// Source: Microsoft Learn / TechNet, "What's New in Kerberos
			// Authentication" (Windows Server 2012 Kerberos armoring
			// section). registrypol_parser.go populates KerberosArmoringClient
			// from the RequireFAST value under a Kerberos\Parameters key -
			// that value belongs to the "Fail authentication requests when
			// Kerberos armoring is not available" policy (Computer
			// Configuration > Administrative Templates > System > Kerberos),
			// a DIFFERENT, separate policy from "Kerberos client support for
			// claims, compound authentication and Kerberos armoring" (which
			// only turns on client-side support/claims, and writes a
			// different registry value). The old recommendation named the
			// wrong policy for the setting actually measured here.
			"recommendation": "Enable 'Fail authentication requests when Kerberos armoring is not available' (Computer Configuration > Administrative Templates > System > Kerberos) via GPO.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewKerberosArmoringClientDetector())
}
