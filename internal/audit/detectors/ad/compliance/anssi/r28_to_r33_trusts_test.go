package anssi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR28KrbtgtRotation_270DaysIsCompliant: ANSSI PA-099 R41
// (p.53) requires rotating krbtgt "chaque année" (once a year), not every 180
// days. A krbtgt password changed 270 days ago is within ANSSI's own
// tolerance and must not be flagged Critical. This test would have FAILED
// against the old 180-day threshold (270 > 180 → flagged) and passes now
// that the threshold matches the source (270 < 365 → compliant).
func TestR28KrbtgtRotation_270DaysIsCompliant(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-502", SAMAccountName: "krbtgt", PasswordLastSet: now.AddDate(0, 0, -270)},
		},
	}
	findings := NewR28KrbtgtRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected krbtgt rotated 270 days ago to be compliant with the 1-year ANSSI R41 threshold, got %+v", findings)
	}
}

// TestR28KrbtgtRotation_400DaysIsFlagged confirms the detector still fires
// once the real ANSSI threshold (1 year) is exceeded.
func TestR28KrbtgtRotation_400DaysIsFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-502", SAMAccountName: "krbtgt", PasswordLastSet: now.AddDate(0, 0, -400)},
		},
	}
	findings := NewR28KrbtgtRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected krbtgt rotated 400 days ago to be flagged, got %+v", findings)
	}
}

// TestR29SIDFiltering_InboundOnlyTrustNotFlagged: ANSSI PA-099
// R24 (p.41) hardens OUTGOING extra-forest trusts only ("relations
// d'approbation SORTANTES extraforêt"). The previous implementation never
// read TrustDirection at all, so a purely inbound external trust without
// SIDFiltering was flagged even though R24 doesn't apply to it. This test
// would have FAILED against the old implementation (flagged regardless of
// direction) and passes now that inbound-only trusts are out of scope.
func TestR29SIDFiltering_InboundOnlyTrustNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "External", TrustDirection: "Inbound", SIDFiltering: false},
		},
	}
	findings := NewR29TrustSIDFilteringDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected an inbound-only external trust to be out of R24's outgoing-only scope, got %+v", findings)
	}
}

// TestR29SIDFiltering_ForestTrustExcluded: R24 hardens forest
// trusts via the ABSENCE of TREAT_AS_EXTERNAL, a distinct attribute not
// collected by the parser - checking SIDFiltering (QUARANTINED_DOMAIN) on a
// forest trust measures the wrong mechanism entirely. The previous
// implementation flagged any forest trust with SIDFiltering=false; this test
// would have FAILED against that (flagged) and passes now that forest
// trusts are excluded rather than checked against the wrong attribute.
func TestR29SIDFiltering_ForestTrustExcluded(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "Forest", TrustDirection: "Outbound", SIDFiltering: false},
		},
	}
	findings := NewR29TrustSIDFilteringDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected forest trusts to be excluded (wrong attribute for that trust type), got %+v", findings)
	}
}

// TestR30SelectiveAuth_InboundOnlyTrustNotFlagged: ANSSI PA-099
// R25+ (p.42) also scopes to outgoing extra-forest trusts only. This test
// would have FAILED against the old direction-blind implementation and
// passes now that inbound-only trusts are excluded.
func TestR30SelectiveAuth_InboundOnlyTrustNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "Forest", TrustDirection: "Inbound", SelectiveAuth: false},
		},
	}
	findings := NewR30TrustSelectiveAuthDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected an inbound-only forest trust to be out of R25+'s outgoing-only scope, got %+v", findings)
	}
}

// TestR31TGTDelegation_CitesR26AndFlagsIncomingOnly: the real
// R31 in PA-099 is about SYSVOL script secrets, unrelated; the actual
// "forbid Kerberos delegation across a trust" rule is R26 (p.43), scoped to
// INCOMING trusts specifically - not "any forest trust" regardless of
// direction, which is what the old implementation checked. This test would
// have FAILED against the old implementation (an outbound-only forest trust
// was flagged) and passes now that only incoming trusts are considered, and
// the citation/description no longer claims the unverifiable bit names.
func TestR31TGTDelegation_CitesR26AndFlagsIncomingOnly(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "Forest", TrustDirection: "Outbound", SelectiveAuth: false},
		},
	}
	findings := NewR31TrustTGTDelegationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected an outbound-only forest trust to be out of R26's incoming-only scope, got %+v", findings)
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "R31") || strings.Contains(desc, "R31 ") {
		t.Errorf("finding must not cite ANSSI R31 (real R31 is unrelated SYSVOL script secrets), got title=%q", title)
	}
	if strings.Contains(desc, "0x200") || strings.Contains(desc, "0x800") || strings.Contains(desc, "AUTH_TARGET_VALIDATION") {
		t.Errorf("description must not cite bit values/attribute names absent from PA-099, got desc=%q", desc)
	}
}

// TestR33ExternalTrustPermissive_EitherProtectionIsSufficient:
// R24's own text frames R25+ (Selective Authentication) as a compensating
// fallback "à défaut" of R24 (SID filtering) - either protection present is
// an acceptable mitigation, not a mandatory AND of both. The previous
// implementation flagged a trust as permissive if EITHER was missing
// (requiring BOTH to be compliant), stricter than the source. This test
// would have FAILED against the old OR-trigger (SIDFiltering off but
// SelectiveAuth on → still flagged) and passes now that having one
// protection is enough.
func TestR33ExternalTrustPermissive_EitherProtectionIsSufficient(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "External", TrustDirection: "Outbound", SelectiveAuth: true, SIDFiltering: false},
		},
	}
	findings := NewR33ExternalTrustPermissiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a trust with Selective Auth (but not SID filtering) to be compliant per R24's own fallback framing, got %+v", findings)
	}
}

// TestR33ExternalTrustPermissive_BothMissingIsFlagged confirms the detector
// still fires when NEITHER protection is present.
func TestR33ExternalTrustPermissive_BothMissingIsFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "External", TrustDirection: "Outbound", SelectiveAuth: false, SIDFiltering: false},
		},
	}
	findings := NewR33ExternalTrustPermissiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a trust with neither protection to be flagged, got %+v", findings)
	}
}
