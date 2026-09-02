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

	// CIS 2.3.9.2: SMB server signing required
	smbSigning := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.RequireSMBSigningServer
	})
	if smbSigning != nil && *smbSigning != 1 {
		violations = append(violations, "CIS 2.3.9.2: SMB server signing not required")
	}

	// CIS 2.3.8.1: SMB client signing required
	smbClientSigning := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.RequireSMBSigningClient
	})
	if smbClientSigning != nil && *smbClientSigning != 1 {
		violations = append(violations, "CIS 2.3.8.1: SMB client signing not required")
	}

	// CIS 2.3.11.8: LDAP signing required
	ldapSigning := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.LDAPServerIntegrity
	})
	if ldapSigning != nil && *ldapSigning < 2 {
		violations = append(violations, "CIS 2.3.11.8: LDAP server signing not required")
	}

	// CIS: LDAP channel binding
	ldapCB := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.LDAPChannelBinding
	})
	if ldapCB != nil && *ldapCB < 2 {
		violations = append(violations, "CIS: LDAP channel binding not set to Always")
	}

	// Domain functional level check
	if data.DomainInfo != nil && data.DomainInfo.FunctionalLevelInt < 7 {
		violations = append(violations, "CIS: Domain functional level below Windows Server 2016")
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
