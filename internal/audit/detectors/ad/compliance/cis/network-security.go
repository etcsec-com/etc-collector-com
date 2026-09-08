package cis

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NetworkSecurityDetector checks CIS network security compliance
type NetworkSecurityDetector struct {
	audit.BaseDetector
}

// NewNetworkSecurityDetector creates a new detector
func NewNetworkSecurityDetector() *NetworkSecurityDetector {
	return &NetworkSecurityDetector{
		BaseDetector: audit.NewBaseDetector("CIS_NETWORK_SECURITY", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *NetworkSecurityDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "CIS Network Security Non-Compliant",
		Description: "Network security settings do not meet CIS Benchmark requirements for SMB signing, LDAP signing, or LDAP channel binding.",
		Count:       0,
		Details: map[string]interface{}{
			"framework": "CIS",
			"benchmark": "CIS Microsoft Windows Server Benchmark",
		},
	}

	var violations []string

	// All four registry-backed checks below used to treat an absent
	// (nil) GPO setting as compliant ("not configured" silently passed).
	// CIS Benchmark items are phrased "Ensure '<setting>' is set to '<value>'"
	// - not configured is itself a finding, not an exemption. Each check now
	// treats nil the same as an explicitly wrong value - but only once GPO
	// data was actually collected: if data.GPOPolicies is nil (SMB/SYSVOL not
	// reached at all this run), that's "we never looked", not "looked and
	// found nothing configured", so all 4 checks are skipped entirely rather
	// than reported as a guaranteed false-positive violation (same principle
	// as the R4/R13 and R79 no-data guards in the anssi package).
	if data.GPOPolicies != nil {
		// CIS 2.3.9.2: SMB server signing required ("Microsoft network server:
		// Digitally sign communications (always)" - confirmed correct, unchanged).
		smbSigning := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
			return rs.RequireSMBSigningServer
		})
		if smbSigning == nil || *smbSigning != 1 {
			violations = append(violations, "CIS 2.3.9.2: SMB server signing not required")
		}

		// CIS 2.3.8.1: SMB client signing required ("Microsoft network client:
		// Digitally sign communications (always)" - confirmed correct, unchanged).
		smbClientSigning := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
			return rs.RequireSMBSigningClient
		})
		if smbClientSigning == nil || *smbClientSigning != 1 {
			violations = append(violations, "CIS 2.3.8.1: SMB client signing not required")
		}

		// Was cited as "CIS 2.3.11.8", which is "Network security: LDAP
		// client signing requirements" - the CLIENT-side setting. This check
		// reads LDAPServerIntegrity (NTDS\Parameters\LDAPServerIntegrity), the
		// SERVER-side, DC-only setting, which CIS numbers under the "Domain
		// controller:" category as 2.3.5.4 (numbered 2.3.5.2-2.3.5.4 depending
		// on benchmark version) - "Domain controller: LDAP server signing
		// requirements", recommended state "Require signing".
		ldapSigning := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
			return rs.LDAPServerIntegrity
		})
		if ldapSigning == nil || *ldapSigning < 2 {
			violations = append(violations, "CIS 2.3.5 (Domain controller: LDAP server signing requirements): not set to Require signing")
		}

		// CIS 2.3.5.3: "Domain controller: LDAP server channel binding token requirements".
		ldapCB := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
			return rs.LDAPChannelBinding
		})
		if ldapCB == nil || *ldapCB < 2 {
			violations = append(violations, "CIS 2.3.5.3 (Domain controller: LDAP server channel binding token requirements): not set to Always")
		}
	}

	// Domain functional level is not a CIS Benchmark control at all
	// (no such item exists in any CIS Windows Server Benchmark) - it was
	// falsely presented as one ("CIS: ..." prefix). Kept as a product-level
	// baseline note, explicitly NOT attributed to CIS.
	if data.DomainInfo != nil && data.DomainInfo.FunctionalLevelInt < 7 {
		violations = append(violations, "Product baseline (not a CIS Benchmark item): Domain functional level below Windows Server 2016 limits available AD security features")
	}

	if len(violations) > 0 {
		finding.Count = len(violations)
		finding.Details["violations"] = violations
		finding.Details["recommendation"] = "Remediate CIS Benchmark violations via Group Policy."
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNetworkSecurityDetector())
}
