package organization

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	ouTestDomainDN = "DC=example,DC=com"
	ouSalesDN      = "OU=Sales," + ouTestDomainDN
	ouDCsCN        = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
)

func ouInventoryData(includeDetails bool) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: includeDetails,
		OUs: []types.OU{
			{DN: ouSalesDN, Name: "Sales"},
			{DN: "OU=Empty," + ouTestDomainDN, Name: "Empty"},
		},
		GPOs: []types.GPO{
			{DN: "CN=" + ouDCsCN + ",CN=Policies,CN=System," + ouTestDomainDN, CN: ouDCsCN, GUID: ouDCsCN, DisplayName: "Sales Baseline"},
		},
		// One GPO linked to the Sales OU (enforced).
		GPOLinks: []audit.GPOLink{
			{GPOCN: ouDCsCN, GPOGuid: "6AC1786C-016F-11D2-945F-00C04FB984F9", LinkedTo: ouSalesDN, LinkEnabled: true, Enforced: true, Order: 0},
		},
		// Direct children of Sales: 2 users, 1 computer, 1 group, plus a nested
		// child-OU. A grandchild user (under the nested OU) must NOT be counted.
		Users: []types.User{
			{DN: "CN=Alice," + ouSalesDN},
			{DN: "CN=Bob," + ouSalesDN},
			{DN: "CN=Grand,OU=Nested," + ouSalesDN}, // grandchild — excluded
		},
		Computers: []types.Computer{
			{DN: "CN=WS01," + ouSalesDN},
		},
		Groups: []types.Group{
			{DN: "CN=SalesTeam," + ouSalesDN},
		},
	}
}

// TestOUInventory_OnePerOU covers acceptance §1: one info finding per OU.
func TestOUInventory_OnePerOU(t *testing.T) {
	d := NewOUInventoryDetector()
	findings := d.Detect(context.Background(), ouInventoryData(true))
	if len(findings) != 2 {
		t.Fatalf("want one finding per OU (2), got %d", len(findings))
	}
	for _, f := range findings {
		if f.Type != "INFO_DOMAIN_OU_INVENTORY" {
			t.Errorf("type = %q, want INFO_DOMAIN_OU_INVENTORY", f.Type)
		}
		if f.Severity != types.SeverityInfo {
			t.Errorf("severity = %q, want info", f.Severity)
		}
	}
}

// TestOUInventory_EmptyWhenNoOUs freezes the nil-return contract.
func TestOUInventory_EmptyWhenNoOUs(t *testing.T) {
	d := NewOUInventoryDetector()
	if got := d.Detect(context.Background(), &audit.DetectorData{IncludeDetails: true}); got != nil {
		t.Fatalf("want nil for no OUs, got %d findings", len(got))
	}
}

// TestOUInventory_EntityShape covers acceptance §2: linkedGpos[], childCounts
// (direct children only), delegations[] — arrays never nil.
func TestOUInventory_EntityShape(t *testing.T) {
	d := NewOUInventoryDetector()
	findings := d.Detect(context.Background(), ouInventoryData(true))

	byName := map[string]types.AffectedEntity{}
	for _, f := range findings {
		e := f.AffectedEntities[0]
		byName[e.Name] = e
	}

	sales := byName["Sales"]
	if sales.Type != types.EntityTypeOU {
		t.Fatalf("entity type = %q, want ou", sales.Type)
	}
	if len(sales.LinkedGpos) != 1 || sales.LinkedGpos[0].Name != "Sales Baseline" || !sales.LinkedGpos[0].Enforced {
		t.Errorf("linkedGpos wrong: %+v", sales.LinkedGpos)
	}
	if sales.ChildCounts == nil {
		t.Fatalf("childCounts must be present")
	}
	// Grandchild user excluded; nested child-OU counted once.
	want := types.EntityChildCounts{Users: 2, Computers: 1, Groups: 1, OUs: 0}
	if *sales.ChildCounts != want {
		t.Errorf("childCounts = %+v, want %+v", *sales.ChildCounts, want)
	}
	if sales.Delegations == nil {
		t.Errorf("delegations must be [] not nil")
	}

	// Empty OU: linkedGpos/delegations non-nil empty, childCounts all zero.
	empty := byName["Empty"]
	if empty.LinkedGpos == nil || len(empty.LinkedGpos) != 0 {
		t.Errorf("empty OU linkedGpos must be [] not nil, got %v", empty.LinkedGpos)
	}
	if empty.ChildCounts == nil || *empty.ChildCounts != (types.EntityChildCounts{}) {
		t.Errorf("empty OU childCounts must be all-zero object, got %+v", empty.ChildCounts)
	}
}

// TestOUInventory_JSONNeverNull covers acceptance §2 at the wire level plus the
// new "ou" marshal case: keys present, arrays [] not null, blockInheritance set.
func TestOUInventory_JSONNeverNull(t *testing.T) {
	d := NewOUInventoryDetector()
	findings := d.Detect(context.Background(), ouInventoryData(true))

	var empty types.AffectedEntity
	for _, f := range findings {
		if f.AffectedEntities[0].Name == "Empty" {
			empty = f.AffectedEntities[0]
		}
	}
	raw, err := json.Marshal(empty)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"linkedGpos", "childCounts", "delegations", "blockInheritance"} {
		if _, ok := m[k]; !ok {
			t.Errorf("ou JSON missing key %q: %s", k, raw)
		}
	}
	for _, k := range []string{"linkedGpos", "delegations"} {
		if _, ok := m[k].([]interface{}); !ok {
			t.Errorf("ou JSON %q must be an array (never null), got %T", k, m[k])
		}
	}
	if _, ok := m["childCounts"].(map[string]interface{}); !ok {
		t.Errorf("ou JSON childCounts must be an object, got %T", m["childCounts"])
	}
}

// TestOU_ExistingShapeUnchanged freezes acceptance §3: a plain ou entity
// (ChildCounts nil, as any non-inventory emitter would produce) keeps its
// generic shape and gains none of the inventory keys.
func TestOU_ExistingShapeUnchanged(t *testing.T) {
	e := types.AffectedEntity{Type: types.EntityTypeOU, DN: "OU=x," + ouTestDomainDN, Name: "x", Description: "desc"}
	raw, _ := json.Marshal(e)
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"linkedGpos", "childCounts", "delegations", "blockInheritance"} {
		if _, ok := m[k]; ok {
			t.Errorf("non-inventory ou entity must NOT carry %q, got %s", k, raw)
		}
	}
	// generic projection preserved.
	if m["description"] != "desc" {
		t.Errorf("generic ou shape lost description: %s", raw)
	}
}
