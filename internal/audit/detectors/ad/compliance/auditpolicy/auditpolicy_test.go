package auditpolicy

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

func TestLevel(t *testing.T) {
	legacyCalled := func(v int) func(*audit.EventAudit) int {
		return func(e *audit.EventAudit) int { return v }
	}

	t.Run("subcategory value wins when present, even with ea also set", func(t *testing.T) {
		adv := map[string]int{"guid-a": 3}
		ea := &audit.EventAudit{}
		v, ok := Level(adv, "guid-a", ea, legacyCalled(0))
		if !ok || v != 3 {
			t.Fatalf("got (%d, %v), want (3, true)", v, ok)
		}
	})

	t.Run("falls back to legacy when subcategory absent but ea present", func(t *testing.T) {
		adv := map[string]int{"guid-other": 3}
		ea := &audit.EventAudit{}
		v, ok := Level(adv, "guid-a", ea, legacyCalled(1))
		if !ok || v != 1 {
			t.Fatalf("got (%d, %v), want (1, true)", v, ok)
		}
	})

	t.Run("no evidence at all: not ok, legacy not invoked", func(t *testing.T) {
		called := false
		legacy := func(e *audit.EventAudit) int { called = true; return 0 }
		_, ok := Level(nil, "guid-a", nil, legacy)
		if ok {
			t.Fatal("expected ok=false when neither audit.csv nor [Event Audit] has data")
		}
		if called {
			t.Fatal("legacy getter must not be invoked when ea is nil — it would panic on a real field access")
		}
	})

	t.Run("empty adv map behaves like nil", func(t *testing.T) {
		ea := &audit.EventAudit{}
		v, ok := Level(map[string]int{}, "guid-a", ea, legacyCalled(2))
		if !ok || v != 2 {
			t.Fatalf("got (%d, %v), want (2, true)", v, ok)
		}
	})
}

func TestGetAdvancedAudit(t *testing.T) {
	t.Run("prefers DC policy over domain policy and any other GPO", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			"{other}":               {AdvancedAudit: map[string]int{"x": 9}},
			defaultDomainPolicyGUID: {AdvancedAudit: map[string]int{"x": 1}},
			defaultDCPolicyGUID:     {AdvancedAudit: map[string]int{"x": 2}},
		}
		got := GetAdvancedAudit(policies)
		if got["x"] != 2 {
			t.Fatalf("got %v, want DC policy's map (x=2)", got)
		}
	})

	t.Run("falls back to domain policy when DC policy has none", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			defaultDomainPolicyGUID: {AdvancedAudit: map[string]int{"x": 1}},
		}
		got := GetAdvancedAudit(policies)
		if got["x"] != 1 {
			t.Fatalf("got %v, want domain policy's map (x=1)", got)
		}
	})

	t.Run("falls back to any GPO when neither default policy has one", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			"{some-other-gpo}": {AdvancedAudit: map[string]int{"x": 5}},
		}
		got := GetAdvancedAudit(policies)
		if got["x"] != 5 {
			t.Fatalf("got %v, want the only GPO's map (x=5)", got)
		}
	})

	t.Run("nil when no GPO has audit.csv data", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			"{some-gpo}": {},
		}
		if got := GetAdvancedAudit(policies); got != nil {
			t.Fatalf("got %v, want nil", got)
		}
	})
}
