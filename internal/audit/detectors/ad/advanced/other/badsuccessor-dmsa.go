package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// BadSuccessorDMSADetector detects dMSA escalation risk via CreateChild on OUs
type BadSuccessorDMSADetector struct {
	audit.BaseDetector
}

// NewBadSuccessorDMSADetector creates a new detector
func NewBadSuccessorDMSADetector() *BadSuccessorDMSADetector {
	return &BadSuccessorDMSADetector{
		BaseDetector: audit.NewBaseDetector("BADSUCCESSOR_DMSA_ESCALATION", audit.CategoryAdvanced),
	}
}

// dmsaObjectClassGUID is the schemaIDGUID of msDS-DelegatedManagedServiceAccount,
// the class a BadSuccessor attacker creates.
//
// An object-specific CreateChild ACE names the schemaIDGUID of the class being
// instantiated — AD matches it exactly, it does NOT walk the class hierarchy.
// So a CreateChild grant for the *computer* class (the common "delegate
// workstation join to the helpdesk" pattern) does NOT permit creating a dMSA,
// even though dMSA derives from computer. The detector previously accepted the
// computer GUID and would have reported every such delegation as a critical
// BadSuccessor exposure (T_023).
const dmsaObjectClassGUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"

// Well-known privileged SIDs to exclude
var privilegedWellKnownSIDs = map[string]bool{
	"S-1-5-18": true, // SYSTEM
	"S-1-5-10": true, // SELF
	"S-1-3-0":  true, // CREATOR OWNER
}

// isPrivilegedTrustee checks if a trustee SID is a privileged principal
func isPrivilegedTrustee(sid string) bool {
	// Check well-known privileged SIDs
	if privilegedWellKnownSIDs[sid] {
		return true
	}

	// Check privileged SID suffixes (e.g., -512 for Domain Admins)
	for suffix := range types.PrivilegedSIDSuffixes {
		if strings.HasSuffix(sid, suffix) {
			return true
		}
	}

	return false
}

// isDMSAContainer reports whether an ACL target is a container a dMSA could
// actually be created IN — an OU or the domain root — rather than an object
// that merely LIVES under one.
//
// The class comes from the engine's DN-indexed cache, which is built from the
// typed LDAP collections plus an orphan lookup pass (engine.go:571-613), so it
// is authoritative. The DN test is only a fallback for a target the cache
// doesn't know (a LookupBatch miss), and it anchors on the LEADING RDN: an
// organizationalUnit's own RDN always starts with "OU=". The original defect
// was `strings.Contains(DN, "OU=")`, which is true for every object nested
// anywhere under any OU — that is how 288 user accounts were reported as
// BadSuccessor containers (T_023).
func isDMSAContainer(dn string, data *audit.DetectorData) bool {
	if meta := data.ObjectByDN[dn]; meta != nil {
		return meta.EntityType == types.EntityTypeOU || meta.EntityType == types.EntityTypeDomain
	}
	return strings.HasPrefix(strings.ToUpper(dn), "OU=")
}

// Detect executes the detection
func (d *BadSuccessorDMSADetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const (
		createChild = 0x1        // ADS_RIGHT_DS_CREATE_CHILD
		genericAll  = 0x10000000 // ADS_RIGHT_GENERIC_ALL — subsumes CreateChild
	)

	var matched []types.ACLEntry

	for _, acl := range data.ACLEntries {
		// Must be an ALLOW ACE
		if !strings.Contains(strings.ToUpper(acl.AceType), "ALLOWED") {
			continue
		}

		// The target must BE a container (OU / domain root), not merely sit
		// under one — the attacker needs somewhere to create the dMSA.
		if !isDMSAContainer(acl.ObjectDN, data) {
			continue
		}

		// ObjectType must be empty (create children of ANY class) or the dMSA
		// class itself. A CreateChild grant scoped to another class cannot
		// create a dMSA.
		guidLower := strings.ToLower(acl.ObjectType)
		if guidLower != "" && guidLower != dmsaObjectClassGUID {
			continue
		}

		// AccessMask must convey the ability to create a child object.
		if acl.AccessMask&(createChild|genericAll) == 0 {
			continue
		}

		// Trustee must NOT be a privileged principal
		if isPrivilegedTrustee(acl.Trustee) {
			continue
		}

		matched = append(matched, acl)
	}

	// Count exposed CONTAINERS, not ACEs: several trustees holding CreateChild
	// on the same OU is one exposed container, not several. The old `count++`
	// per ACE inflated 286 objects into 288 findings (T_023).
	entities := uniqueContainerEntities(matched, data)
	count := len(entities)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Delegated Managed Service Account (dMSA) Escalation Risk (BadSuccessor)",
		Description: "Users with CreateChild permissions on OUs could create delegated Managed Service Accounts (dMSA) that inherit the permissions of any existing account by setting it as a predecessor. This Windows Server 2025 vulnerability (CVE-2025-21293) allows privilege escalation to Domain Admin.",
		Count:       count,
	}

	if data.IncludeDetails && count > 0 {
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

// uniqueContainerEntities returns one entity per unique exposed container,
// keeping the aclEntry shape so the report says WHO holds the right on WHAT —
// without it a customer can see the count but not the grant to revoke.
//
// A pure CreateChild mask has no name in the v3.1.29 §4 right enum, so
// ACLEntryToAffectedEntity returns the zero value for it; in that case we fall
// back to the typed container entity rather than dropping it, so `count` can
// never exceed the entities the customer receives (the DET_2 failure mode).
func uniqueContainerEntities(matched []types.ACLEntry, data *audit.DetectorData) []types.AffectedEntity {
	seen := make(map[string]bool, len(matched))
	out := make([]types.AffectedEntity, 0, len(matched))
	for _, acl := range matched {
		if acl.ObjectDN == "" || seen[acl.ObjectDN] {
			continue
		}
		seen[acl.ObjectDN] = true
		if ent := audit.ACLEntryToAffectedEntity(acl, data.ObjectByDN, data.ObjectBySID); ent.Type != "" {
			out = append(out, ent)
			continue
		}
		out = append(out, data.EntityForDN(acl.ObjectDN))
	}
	return out
}

func init() {
	audit.MustRegister(NewBadSuccessorDMSADetector())
}
