package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OUUnprotectedDetector detects OUs without accidental deletion protection
type OUUnprotectedDetector struct {
	audit.BaseDetector
}

// NewOUUnprotectedDetector creates a new detector
func NewOUUnprotectedDetector() *OUUnprotectedDetector {
	return &OUUnprotectedDetector{
		BaseDetector: audit.NewBaseDetector("OU_UNPROTECTED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *OUUnprotectedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build a set of OUs protected from deletion by checking ACLs.
	// The "Protect object from accidental deletion" checkbox in AD adds a
	// Deny Delete + Deny Delete Subtree ACE for Everyone (S-1-1-0).
	// AccessMask DELETE = 0x10000, DELETE_TREE = 0x40 (via control access)
	const deleteRight = 0x10000
	protectedOUs := make(map[string]bool)

	for _, acl := range data.ACLEntries {
		if strings.EqualFold(acl.AceType, "ACCESS_DENIED_ACE") &&
			acl.Trustee == "S-1-1-0" &&
			(acl.AccessMask&deleteRight) != 0 {
			protectedOUs[acl.ObjectDN] = true
		}
	}

	var unprotected []string
	for _, ou := range data.OUs {
		if !protectedOUs[ou.DN] {
			unprotected = append(unprotected, ou.DN)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Organizational Units Without Deletion Protection",
		Description: "Organizational Units (OUs) without 'Protect object from accidental deletion' enabled can be accidentally deleted, causing mass disruption.",
		Count:       len(unprotected),
	}

	if data.IncludeDetails && len(unprotected) > 0 {
		entities := make([]types.AffectedEntity, 0, len(unprotected))
		for _, dn := range unprotected {
			entities = append(entities, types.AffectedEntity{
				Type: "ou",
				DN:   dn,
			})
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOUUnprotectedDetector())
}
