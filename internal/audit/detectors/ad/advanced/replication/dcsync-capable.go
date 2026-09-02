package replication

import (
	"context"
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DcsyncCapableDetector detects accounts capable of DCSync
type DcsyncCapableDetector struct {
	audit.BaseDetector
}

// NewDcsyncCapableDetector creates a new detector
func NewDcsyncCapableDetector() *DcsyncCapableDetector {
	return &DcsyncCapableDetector{
		BaseDetector: audit.NewBaseDetector("DCSYNC_CAPABLE", audit.CategoryAdvanced),
	}
}

// DCSync replication right GUIDs
const (
	DSReplicationGetChanges    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	DSReplicationGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
)

// isAdminSID checks if a SID is a well-known admin SID that should have DCSync rights
func isAdminSID(sid, domainSID string) bool {
	adminSIDs := []string{
		domainSID + "-512", // Domain Admins
		domainSID + "-519", // Enterprise Admins
		domainSID + "-518", // Schema Admins
		"S-1-5-32-544",     // Administrators
		"S-1-5-18",         // SYSTEM
		"S-1-5-32-548",     // Account Operators
	}

	for _, adminSID := range adminSIDs {
		if sid == adminSID {
			return true
		}
	}
	return false
}

// isDCSyncGUID checks if the ObjectType GUID is a DCSync replication right
func isDCSyncGUID(guid string) bool {
	guidLower := strings.ToLower(guid)
	return guidLower == strings.ToLower(DSReplicationGetChanges) ||
		guidLower == strings.ToLower(DSReplicationGetChangesAll)
}

// Detect executes the detection
func (d *DcsyncCapableDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		finding := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityHigh,
			Category:    string(d.Category()),
			Title:       "DCSync Capable",
			Description: "Account with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights. Can extract all password hashes.",
			Count:       0,
			Details: map[string]interface{}{
				"note": "Domain information not available for analysis.",
			},
		}
		return []types.Finding{finding}
	}

	domainSID := data.DomainInfo.DomainSID
	domainDN := data.DomainInfo.DomainDN

	// Track trustees with DCSync rights
	dcsyncTrustees := make(map[string]map[string]bool) // trustee -> set of replication GUIDs
	var affectedEntities []types.AffectedEntity

	// Check ACL entries on the domain root DN for DCSync rights
	for _, acl := range data.ACLEntries {
		// Must be on the domain root
		if !strings.EqualFold(acl.ObjectDN, domainDN) {
			continue
		}

		// Skip deny ACEs. This used to compare AceType to the literal "deny",
		// but acl_parser.go emits Windows-style values (ACCESS_ALLOWED,
		// ACCESS_DENIED, ACCESS_ALLOWED_OBJECT, ACCESS_DENIED_OBJECT,
		// SYSTEM_AUDIT…), so the guard could never be true — dead code that
		// would have counted a DENY DCSync ace as a grant (T_024 / DET_10).
		if !audit.IsGrantACE(acl.AceType) {
			continue
		}

		// Check if this is a DCSync replication right
		if !isDCSyncGUID(acl.ObjectType) {
			continue
		}

		// Skip if trustee is an admin SID
		trusteeSID := acl.Trustee
		if isAdminSID(trusteeSID, domainSID) {
			continue
		}

		// Track this trustee's replication rights
		if dcsyncTrustees[trusteeSID] == nil {
			dcsyncTrustees[trusteeSID] = make(map[string]bool)
		}
		dcsyncTrustees[trusteeSID][strings.ToLower(acl.ObjectType)] = true
	}

	// Only count trustees that have BOTH replication rights
	var dcsyncCapable []string
	for trustee, rights := range dcsyncTrustees {
		hasGetChanges := rights[strings.ToLower(DSReplicationGetChanges)]
		hasGetChangesAll := rights[strings.ToLower(DSReplicationGetChangesAll)]

		if hasGetChanges && hasGetChangesAll {
			dcsyncCapable = append(dcsyncCapable, trustee)
		}
	}

	// Sorted by SID (T_046/B_048): dcsyncTrustees is a map, so the range
	// above visits trustees in a randomized order — same input, different
	// JSON, different sha256 across runs. Sort before building entities so
	// emission order is deterministic regardless of resolution (a resolved
	// trustee's entity carries a DN, an unresolved one doesn't — the SID
	// itself is the one key both always have).
	sort.Strings(dcsyncCapable)

	if data.IncludeDetails {
		for _, trustee := range dcsyncCapable {
			ent := audit.SIDToEntityWithCache(trustee, data)
			ent.Description = "Has DS-Replication-Get-Changes and DS-Replication-Get-Changes-All"
			affectedEntities = append(affectedEntities, ent)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DCSync Capable",
		Description: "Principals with both DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights on the domain root. These accounts can perform DCSync attacks to extract all password hashes.",
		Count:       len(dcsyncCapable),
	}

	if data.IncludeDetails && len(affectedEntities) > 0 {
		finding.AffectedEntities = affectedEntities
		finding.Details = map[string]interface{}{
			"recommendation": "Remove DCSync replication rights from non-admin principals. Only Domain Controllers should have these rights.",
			"replicationRights": []string{
				"DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)",
				"DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDcsyncCapableDetector())
}
