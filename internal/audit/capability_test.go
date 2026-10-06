package audit

import "testing"

func TestRequiredCapability_DefaultsToBaseline(t *testing.T) {
	if got := RequiredCapability("SOME_UNLISTED_DETECTOR"); got != CapLDAP {
		t.Fatalf("an unlisted detector must default to the LDAP baseline, got %q", got)
	}
}

func TestConsentGate_BaselineAlwaysAllowed(t *testing.T) {
	// The zero grant (no escalations consented) must still allow every
	// baseline detector.
	g := newConsentGate(nil)
	if !g.allowsID("ANY_BASELINE_DETECTOR") {
		t.Fatal("a baseline detector must run with no granted escalations")
	}
}

func TestConsentGate_FailClosedOnUngrantedEscalation(t *testing.T) {
	// Register a temporary escalated detector, then remove it so the global
	// table is untouched for other tests.
	const id = "TEST_NEEDS_REGISTRY"
	detectorCapability[id] = CapRemoteRegistry
	defer delete(detectorCapability, id)

	// No escalation granted → the escalated detector is DENIED (fail-closed).
	if newConsentGate(nil).allowsID(id) {
		t.Fatal("an escalated detector must be denied when its capability is not granted")
	}

	// A different escalation granted → still denied (the specific capability
	// must match, not merely "some escalation").
	if newConsentGate([]Capability{CapSysvol}).allowsID(id) {
		t.Fatal("granting an unrelated capability must not unlock a different escalation")
	}

	// The matching escalation granted → allowed.
	if !newConsentGate([]Capability{CapRemoteRegistry}).allowsID(id) {
		t.Fatal("an escalated detector must run once its capability is granted")
	}
}

// TestDetectorCapability_SysvolEntriesDeniedWhenRefused is the table-level
// counterpart to the engine-level TestCollectionConsent_
// RefusedSysvolExcludesDependentDetectors: every detector declared as
// CapSysvol here must actually be denied once SYSVOL is refused. Guarded
// against an emptied table - without the guard this test would iterate zero
// times and pass without proving anything.
func TestDetectorCapability_SysvolEntriesDeniedWhenRefused(t *testing.T) {
	ids := SysvolDependentDetectors()
	if len(ids) == 0 {
		t.Fatal("detectorCapability has no CapSysvol entries - this test would pass vacuously; " +
			"populate it with the detectors whose verdict depends entirely on SYSVOL")
	}

	refused := newConsentGateWithDenials(nil, []Capability{CapSysvol})
	for _, id := range ids {
		if refused.allowsID(id) {
			t.Errorf("%s is declared CapSysvol but is still allowed once SYSVOL is refused", id)
		}
	}
}

// TestDetectorCapability_SysvolEntriesAllowedByDefault is the non-regression
// half: with nothing refused, every SYSVOL-dependent detector is still
// allowed - CapSysvol is a baseline capability, so populating the table must
// not change default (no-refusal) behavior at all.
func TestDetectorCapability_SysvolEntriesAllowedByDefault(t *testing.T) {
	baseline := newConsentGate(nil)
	for _, id := range SysvolDependentDetectors() {
		if !baseline.allowsID(id) {
			t.Errorf("%s is denied with no refusal in effect - CapSysvol is baseline and must be allowed by default", id)
		}
	}
}

// TestSysvolRefusalDetail_ComputesAffectedAndCounts exercises the pure diff
// helper Run() uses to enrich the CAPABILITY_REFUSED_SYSVOL warning: the IDs
// present in wouldHaveRun but missing from actual, plus both counts.
func TestSysvolRefusalDetail_ComputesAffectedAndCounts(t *testing.T) {
	a := &testDetector{BaseDetector: NewBaseDetector("A", CategoryGPO)}
	b := &testDetector{BaseDetector: NewBaseDetector("B", CategoryGPO)}
	c := &testDetector{BaseDetector: NewBaseDetector("C", CategoryGPO)}

	affected, total, remaining := sysvolRefusalDetail([]Detector{a, b, c}, []Detector{b})
	if total != 3 || remaining != 1 {
		t.Fatalf("total=%d remaining=%d, want total=3 remaining=1", total, remaining)
	}
	if len(affected) != 2 || affected[0] != "A" || affected[1] != "C" {
		t.Fatalf("affected=%v, want [A C]", affected)
	}
}
