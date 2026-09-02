package computer

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GenericAllDetector detects GenericAll permission on computer objects
type GenericAllDetector struct {
	audit.BaseDetector
}

// NewGenericAllDetector creates a new detector
func NewGenericAllDetector() *GenericAllDetector {
	return &GenericAllDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_ACL_GENERICALL", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *GenericAllDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// GENERIC_ALL raw value
	const genericAll = 0x10000000
	// Full control mask for AD objects (all specific AD rights + standard rights)
	const adFullControl = 0x000f01ff

	// Build a Set of lowercase computer DNs for fast lookup
	computerDNSet := make(map[string]bool)
	for _, c := range data.Computers {
		computerDNSet[strings.ToLower(c.DN)] = true
	}

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		dn := strings.ToLower(ace.ObjectDN)

		// Check if DN is a computer object
		isComputer := false
		if len(computerDNSet) > 0 {
			isComputer = computerDNSet[dn]
		} else {
			// Fallback: heuristic detection (less accurate)
			isComputer = strings.Contains(dn, "ou=computers") ||
				strings.Contains(dn, "ou=workstations") ||
				strings.Contains(dn, "ou=servers") ||
				strings.Contains(dn, "cn=computers,")
		}

		if !isComputer {
			continue
		}

		// A DENY ace grants nothing, and built-in admins hold full control on
		// every computer object by construction — without these filters the
		// detector reported all 74 of 74 computers, the same baseline-noise
		// defect as the ACL_* family (T_024).
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}

		// Check for raw GENERIC_ALL or Full Control
		if (ace.AccessMask&genericAll) != 0 || (ace.AccessMask&adFullControl) == adFullControl {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Computer ACL GenericAll",
		Description: "GenericAll permission on computer objects. Attacker with this permission can take over the computer, configure Resource-Based Constrained Delegation (RBCD), or extract credentials.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(affected, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGenericAllDetector())
}
