package dangerous

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ReanimateTombstonesDetector detects Reanimate-Tombstones extended right
type ReanimateTombstonesDetector struct {
	audit.BaseDetector
}

// NewReanimateTombstonesDetector creates a new detector
func NewReanimateTombstonesDetector() *ReanimateTombstonesDetector {
	return &ReanimateTombstonesDetector{
		BaseDetector: audit.NewBaseDetector("REANIMATE_TOMBSTONES_RIGHT", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *ReanimateTombstonesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Reanimate-Tombstones extended right GUID
	const reanimateGUID = "45ec5156-db7e-47bb-b53f-dbeb2d03c40f"

	// Build privileged SIDs set
	privilegedSIDs := make(map[string]bool)
	privilegedSIDs["S-1-5-18"] = true // SYSTEM
	privilegedSIDs["S-1-3-0"] = true  // Creator Owner
	privilegedSIDs["S-1-5-10"] = true // SELF
	if data.DomainInfo != nil && data.DomainInfo.DomainSID != "" {
		for suffix := range types.PrivilegedSIDSuffixes {
			privilegedSIDs[data.DomainInfo.DomainSID+suffix] = true
		}
	}

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if !strings.Contains(ace.AceType, "ALLOWED") {
			continue
		}
		if (ace.AccessMask & types.MaskControlAccess) == 0 {
			continue
		}
		if strings.ToLower(ace.ObjectType) != reanimateGUID {
			continue
		}
		if privilegedSIDs[ace.Trustee] {
			continue
		}
		affected = append(affected, ace)
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Objects with Reanimate-Tombstones Extended Right",
		Description: "Non-privileged principals have the Reanimate-Tombstones extended right. This allows restoring deleted objects from the AD recycle bin or tombstone, potentially recovering sensitive or previously removed accounts.",
		Count:       len(uniqueObjects),
		Details: map[string]interface{}{
			"risk":           "Recovery of deleted sensitive objects including privileged accounts.",
			"recommendation": "Remove Reanimate-Tombstones rights from non-privileged accounts.",
		},
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
	audit.MustRegister(NewReanimateTombstonesDetector())
}
