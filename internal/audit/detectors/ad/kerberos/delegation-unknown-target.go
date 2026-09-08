package kerberos

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DelegationUnknownTargetDetector checks for constrained delegation to SPNs that don't resolve to known computers
type DelegationUnknownTargetDetector struct {
	audit.BaseDetector
}

// NewDelegationUnknownTargetDetector creates a new detector
func NewDelegationUnknownTargetDetector() *DelegationUnknownTargetDetector {
	return &DelegationUnknownTargetDetector{
		BaseDetector: audit.NewBaseDetector("DELEGATION_UNKNOWN_TARGET", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *DelegationUnknownTargetDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build set of known computer DNS hostnames and SAMAccountNames
	knownHosts := make(map[string]bool)
	for _, c := range data.Computers {
		if c.DNSHostName != "" {
			knownHosts[strings.ToLower(c.DNSHostName)] = true
		}
		if c.SAMAccountName != "" {
			// Strip trailing $ from computer account name
			name := strings.TrimSuffix(strings.ToLower(c.SAMAccountName), "$")
			knownHosts[name] = true
		}
	}

	var affected []types.User
	unknownTargets := make(map[string][]string) // user → unknown SPNs

	for _, u := range data.Users {
		if len(u.AllowedToDelegateTo) == 0 {
			continue
		}
		var unknownSPNs []string
		for _, spn := range u.AllowedToDelegateTo {
			host := extractHostFromSPN(spn)
			if host == "" {
				continue
			}
			hostLower := strings.ToLower(host)
			if !knownHosts[hostLower] {
				unknownSPNs = append(unknownSPNs, spn)
			}
		}
		if len(unknownSPNs) > 0 {
			affected = append(affected, u)
			unknownTargets[u.SAMAccountName] = unknownSPNs
		}
	}

	// Also check computers with constrained delegation
	var affectedComputers []types.Computer
	for _, c := range data.Computers {
		if len(c.AllowedToDelegateTo) == 0 {
			continue
		}
		var unknownSPNs []string
		for _, spn := range c.AllowedToDelegateTo {
			host := extractHostFromSPN(spn)
			if host == "" {
				continue
			}
			hostLower := strings.ToLower(host)
			if !knownHosts[hostLower] {
				unknownSPNs = append(unknownSPNs, spn)
			}
		}
		if len(unknownSPNs) > 0 {
			affectedComputers = append(affectedComputers, c)
			unknownTargets[c.SAMAccountName] = unknownSPNs
		}
	}

	totalCount := len(affected) + len(affectedComputers)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Constrained Delegation to Unknown Target",
		Description: "Accounts with constrained delegation configured to SPNs whose target hostname does not match any known computer in Active Directory. This may indicate stale delegation entries pointing to decommissioned servers, or delegation to external/unknown systems. Attackers could potentially register a machine with the missing hostname to intercept delegated credentials.",
		Count:       totalCount,
	}

	if data.IncludeDetails && totalCount > 0 {
		var entities []types.AffectedEntity
		if len(affected) > 0 {
			entities = append(entities, helpers.ToAffectedUserEntities(affected)...)
		}
		if len(affectedComputers) > 0 {
			entities = append(entities, helpers.ToAffectedComputerEntities(affectedComputers)...)
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"unknownTargets": unknownTargets,
		}
	}

	return []types.Finding{finding}
}

// extractHostFromSPN extracts the hostname from a SPN like "cifs/server.domain.com" or "http/webserver"
func extractHostFromSPN(spn string) string {
	parts := strings.SplitN(spn, "/", 2)
	if len(parts) < 2 {
		return ""
	}
	host := parts[1]
	// Remove port if present (e.g., "server:1433")
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

func init() {
	audit.MustRegister(NewDelegationUnknownTargetDetector())
}
