package gpo

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// domainDN and the two GPO GUIDs used across the table.
const (
	gpoTestDomainDN = "DC=example,DC=com"
	gpoLinkedCN     = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
	gpoOrphanCN     = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
)

func gpoInventoryData(includeDetails bool) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: includeDetails,
		GPOs: []types.GPO{
			{DN: "CN=" + gpoLinkedCN + ",CN=Policies,CN=System," + gpoTestDomainDN, CN: gpoLinkedCN, GUID: gpoLinkedCN, Name: gpoLinkedCN, DisplayName: "Default Domain Policy", Enabled: true},
			{DN: "CN=" + gpoOrphanCN + ",CN=Policies,CN=System," + gpoTestDomainDN, CN: gpoOrphanCN, GUID: gpoOrphanCN, Name: gpoOrphanCN, DisplayName: "Unlinked Policy", Enabled: true},
		},
		// gpoLinkedCN linked to both the domain root and one OU; the orphan has no link.
		GPOLinks: []audit.GPOLink{
			{GPOCN: gpoLinkedCN, GPOGuid: "31B2F340-016D-11D2-945F-00C04FB984F9", LinkedTo: gpoTestDomainDN, LinkEnabled: true, Enforced: false, Order: 0},
			{GPOCN: gpoLinkedCN, GPOGuid: "31B2F340-016D-11D2-945F-00C04FB984F9", LinkedTo: "OU=Sales," + gpoTestDomainDN, LinkEnabled: true, Enforced: true, Order: 1},
		},
		// One control ACE (GenericAll) + one read ACE on the linked GPO.
		GPOAcls: []audit.GPOAcl{
			{GPODN: "CN=" + gpoLinkedCN + ",CN=Policies,CN=System," + gpoTestDomainDN, Trustee: "S-1-5-32-544", TrusteeSID: "S-1-5-32-544", AccessMask: 0x10000000, AceType: "AccessAllowed"},
			{GPODN: "CN=" + gpoLinkedCN + ",CN=Policies,CN=System," + gpoTestDomainDN, Trustee: "S-1-5-11", TrusteeSID: "S-1-5-11", AccessMask: 0x20000, AceType: "AccessAllowed"},
		},
	}
}

// TestGPOInventory_OnePerGPO covers acceptance §1: one finding per GPO, info
// severity, correct type — emitted even though no GPO carries a vuln finding.
func TestGPOInventory_OnePerGPO(t *testing.T) {
	d := NewGPOInventoryDetector()
	findings := d.Detect(context.Background(), gpoInventoryData(true))
	if len(findings) != 2 {
		t.Fatalf("want one finding per GPO (2), got %d", len(findings))
	}
	for _, f := range findings {
		if f.Type != "INFO_DOMAIN_GPO_INVENTORY" {
			t.Errorf("type = %q, want INFO_DOMAIN_GPO_INVENTORY", f.Type)
		}
		if f.Severity != types.SeverityInfo {
			t.Errorf("severity = %q, want info", f.Severity)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("want exactly one entity per finding, got %d", len(f.AffectedEntities))
		}
	}
}

// TestGPOInventory_EmptyWhenNoGPOs freezes the nil-return contract.
func TestGPOInventory_EmptyWhenNoGPOs(t *testing.T) {
	d := NewGPOInventoryDetector()
	if got := d.Detect(context.Background(), &audit.DetectorData{IncludeDetails: true}); got != nil {
		t.Fatalf("want nil for no GPOs, got %d findings", len(got))
	}
}

// TestGPOInventory_NoEntitiesWithoutDetails freezes the IncludeDetails gate.
func TestGPOInventory_NoEntitiesWithoutDetails(t *testing.T) {
	d := NewGPOInventoryDetector()
	for _, f := range d.Detect(context.Background(), gpoInventoryData(false)) {
		if f.AffectedEntities != nil {
			t.Errorf("entities must be omitted when IncludeDetails=false, got %d", len(f.AffectedEntities))
		}
	}
}

// TestGPOInventory_EntityShape covers acceptance §2: the entity carries
// linkedTo[]/permissions/blockInheritance/wmiFilter/delegations[], arrays never
// nil, links/permissions derived from the collected data.
func TestGPOInventory_EntityShape(t *testing.T) {
	d := NewGPOInventoryDetector()
	findings := d.Detect(context.Background(), gpoInventoryData(true))

	byName := map[string]types.AffectedEntity{}
	for _, f := range findings {
		e := f.AffectedEntities[0]
		byName[e.Name] = e
	}

	linked := byName["Default Domain Policy"]
	if linked.Type != types.EntityTypeGPO {
		t.Fatalf("entity type = %q, want gpo", linked.Type)
	}
	if len(linked.LinkedTo) != 2 {
		t.Fatalf("linkedTo len = %d, want 2", len(linked.LinkedTo))
	}
	// Scope classification + enforced flag threaded from the link.
	var sawDomain, sawEnforcedOU bool
	for _, l := range linked.LinkedTo {
		if l.Scope == "Domain" && l.DN == gpoTestDomainDN {
			sawDomain = true
		}
		if l.Scope == "OU" && l.Enforced {
			sawEnforcedOU = true
		}
	}
	if !sawDomain || !sawEnforcedOU {
		t.Errorf("linkedTo scopes/enforced wrong: %+v", linked.LinkedTo)
	}
	// permissions grouped by trustee: Administrators → GenericAll, Auth Users → Read fallback.
	if len(linked.Delegations) != 2 {
		t.Fatalf("permissions len = %d, want 2 (%+v)", len(linked.Delegations), linked.Delegations)
	}
	rightsBySID := map[string][]string{}
	for _, p := range linked.Delegations {
		rightsBySID[p.Trustee] = p.Rights
	}
	if got := rightsBySID["S-1-5-32-544"]; len(got) != 1 || got[0] != "GenericAll" {
		t.Errorf("admins rights = %v, want [GenericAll]", got)
	}
	if got := rightsBySID["S-1-5-11"]; len(got) != 1 || got[0] != "Read" {
		t.Errorf("auth-users rights = %v, want [Read] (fallback)", got)
	}

	// Orphan GPO: arrays present and non-nil, just empty.
	orphan := byName["Unlinked Policy"]
	if orphan.LinkedTo == nil || len(orphan.LinkedTo) != 0 {
		t.Errorf("orphan linkedTo must be [] not nil, got %v", orphan.LinkedTo)
	}
	if orphan.Delegations == nil || len(orphan.Delegations) != 0 {
		t.Errorf("orphan permissions must be [] not nil, got %v", orphan.Delegations)
	}
}

// TestGPOInventory_JSONNeverNull covers acceptance §2's "all [] never nil" at
// the wire level: the custom MarshalJSON emits linkedTo/permissions/delegations
// as [] (not null) and blockInheritance/wmiFilter keys are always present.
func TestGPOInventory_JSONNeverNull(t *testing.T) {
	d := NewGPOInventoryDetector()
	findings := d.Detect(context.Background(), gpoInventoryData(true))

	var orphan types.AffectedEntity
	for _, f := range findings {
		if f.AffectedEntities[0].Name == "Unlinked Policy" {
			orphan = f.AffectedEntities[0]
		}
	}
	raw, err := json.Marshal(orphan)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"linkedTo", "permissions", "delegations", "wmiFilter", "blockInheritance"} {
		if _, ok := m[k]; !ok {
			t.Errorf("gpo JSON missing key %q: %s", k, raw)
		}
	}
	for _, k := range []string{"linkedTo", "permissions", "delegations"} {
		if arr, ok := m[k].([]interface{}); !ok {
			t.Errorf("gpo JSON %q must be an array (never null), got %T", k, m[k])
		} else if arr == nil {
			t.Errorf("gpo JSON %q is null, want []", k)
		}
	}
	if m["wmiFilter"] != nil {
		t.Errorf("wmiFilter should be null when uncollected, got %v", m["wmiFilter"])
	}
}

// TestGPO_ExistingShapeUnchanged freezes acceptance §3: a plain gpo entity (as
// emitted by non-inventory detectors, LinkedTo nil) keeps its {type,dn,name}
// shape and gains none of the inventory keys.
func TestGPO_ExistingShapeUnchanged(t *testing.T) {
	e := types.AffectedEntity{Type: types.EntityTypeGPO, DN: "CN=x", Name: "x"}
	raw, _ := json.Marshal(e)
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"linkedTo", "permissions", "delegations", "wmiFilter", "blockInheritance", "enabled"} {
		if _, ok := m[k]; ok {
			t.Errorf("non-inventory gpo entity must NOT carry %q, got %s", k, raw)
		}
	}
}
