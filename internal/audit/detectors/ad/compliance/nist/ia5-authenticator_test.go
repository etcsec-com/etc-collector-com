package nist

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestIA5Authenticator_ShortRotationDoesNotViolate is a red->green
// test: before the fix, a MaxPwdAge > 60 (or 0, meaning "never expires" at
// the domain level) was flagged as an "IA-5(1)(d)" NIST violation. NIST SP
// 800-63B-4 Sec. 3.1.1.2 SHALL NOT require periodic password changes absent
// evidence of compromise - a domain with no forced rotation (MaxPwdAge=0)
// is following modern NIST doctrine, not violating it, so it must not be
// flagged on that basis. This uses a compliant MinPwdLength/PwdHistoryLength
// so the only variable under test is MaxPwdAge.
func TestIA5Authenticator_ShortRotationDoesNotViolate(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 - MaxPwdAge=0 (no forced rotation) follows SP 800-63B-4, it is not a violation", findings[0].Count)
	}
}

// TestIA5Authenticator_PasswordNeverExpires_DoesNotMarkNonCompliant is a
// red->green test for the second instance of the same contradiction:
// before the fix, >10 enabled accounts with UF_DONT_EXPIRE_PASSWD set were
// counted as an "IA-5(1)(d)" violation and flipped the whole finding to
// non-compliant. Under SP 800-63B-4, a never-expiring password isn't itself
// a rotation-doctrine violation, so this must no longer drive Count>0 (the
// raw count is still surfaced in Details for manual review).
func TestIA5Authenticator_PasswordNeverExpires_DoesNotMarkNonCompliant(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	users := make([]types.User, 0, 11)
	for i := 0; i < 11; i++ {
		users = append(users, types.User{SAMAccountName: "svc", UserAccountControl: 0x10000})
	}
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
		Users:      users,
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 - password-never-expires alone is not an IA-5(1)(d) violation under SP 800-63B-4", findings[0].Count)
	}
	if got, _ := findings[0].Details["passwordNeverExpires"].(int); got != 11 {
		t.Errorf("Details[passwordNeverExpires] = %v, want 11 (still surfaced for manual review)", findings[0].Details["passwordNeverExpires"])
	}
}

// TestIA5Authenticator_PasswordNotRequired_StillViolates confirms the
// unrelated UF_PASSWD_NOTREQD check (accounts with no password requirement
// at all) is untouched by the rotation-doctrine fix and still flags. Uses
// the literal 0x220 (NORMAL_ACCOUNT | PASSWD_NOTREQD), not the constant
// under test, so a drift in that constant cannot mask a break here.
func TestIA5Authenticator_PasswordNotRequired_StillViolates(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
		Users:      []types.User{{SAMAccountName: "nopass", UserAccountControl: 0x220}},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1 - an account with no password required at all is a genuine authenticator-existence violation", findings[0].Count)
	}
	if got, _ := findings[0].Details["passwordNotRequired"].(int); got != 1 {
		t.Errorf("Details[passwordNotRequired] = %v, want 1", findings[0].Details["passwordNotRequired"])
	}
}

// TestIA5Authenticator_InterdomainTrustAccount_NotCountedAsPasswordNotRequired
// covers an enabled interdomain trust account, which carries PASSWD_NOTREQD
// (0x20) by Windows default alongside UAC 0x800 (KB 305144). Literal 0x820
// (INTERDOMAIN_TRUST_ACCOUNT | PASSWD_NOTREQD), distinct from
// types.UACInterdomainTrustAccount, so a drift in that constant's value
// cannot mask a regression here.
func TestIA5Authenticator_InterdomainTrustAccount_NotCountedAsPasswordNotRequired(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
		Users:      []types.User{{SAMAccountName: "LEGACY$", UserAccountControl: 0x820}},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 - an interdomain trust account is not a password-not-required violation (KB 305144)", findings[0].Count)
	}
	if got, _ := findings[0].Details["passwordNotRequired"].(int); got != 0 {
		t.Errorf("Details[passwordNotRequired] = %v, want 0", findings[0].Details["passwordNotRequired"])
	}
	if got, _ := findings[0].Details["passwordNeverExpires"].(int); got != 0 {
		t.Errorf("Details[passwordNeverExpires] = %v, want 0 - trust account excluded from both counts", findings[0].Details["passwordNeverExpires"])
	}
}

// TestIA5Authenticator_InterdomainTrustAccount_PlusOrdinaryAccount_BothCounts
// mixes the excluded trust account (0x820) with an ordinary account that
// genuinely has no password required (0x220, literal, distinct from
// types.UACInterdomainTrustAccount and uacPasswordNotRequired): the guard
// must exclude only the trust account, not silence the whole detector.
func TestIA5Authenticator_InterdomainTrustAccount_PlusOrdinaryAccount_BothCounts(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
		Users: []types.User{
			{SAMAccountName: "LEGACY$", UserAccountControl: 0x820},
			{SAMAccountName: "plant", UserAccountControl: 0x220},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1 - the ordinary account still violates, the trust account is excluded", findings[0].Count)
	}
	if got, _ := findings[0].Details["passwordNotRequired"].(int); got != 1 {
		t.Errorf("Details[passwordNotRequired] = %v, want 1 - only the ordinary account counted", findings[0].Details["passwordNotRequired"])
	}
}

// TestIA5Authenticator_InterdomainTrustAccount_WithoutPasswordNotRequired
// uses 0x120 (NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_TEMP_DUPLICATE, no
// PASSWD_NOTREQD and no 0x800): confirms an ordinary never-expires account,
// with neither trust bit nor no-password bit set, is unaffected by the
// guard and still surfaced in the never-expires count only.
func TestIA5Authenticator_OrdinaryNeverExpiresAccount_WithoutTrustBit(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
		Users:      []types.User{{SAMAccountName: "svc_ordinary", UserAccountControl: 0x10100}},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 - never-expires alone is not a violation", findings[0].Count)
	}
	if got, _ := findings[0].Details["passwordNeverExpires"].(int); got != 1 {
		t.Errorf("Details[passwordNeverExpires] = %v, want 1", findings[0].Details["passwordNeverExpires"])
	}
	if got, _ := findings[0].Details["passwordNotRequired"].(int); got != 0 {
		t.Errorf("Details[passwordNotRequired] = %v, want 0", findings[0].Details["passwordNotRequired"])
	}
}

// TestIA5Authenticator_DisabledInterdomainTrustAccount_AlreadyExcluded uses
// 0x822 (INTERDOMAIN_TRUST_ACCOUNT | PASSWD_NOTREQD | ACCOUNTDISABLE): the
// pre-existing Enabled() filter already excludes it, independent of the new
// 0x800 guard - both must agree on exclusion.
func TestIA5Authenticator_DisabledInterdomainTrustAccount_AlreadyExcluded(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
		Users:      []types.User{{SAMAccountName: "LEGACY$", UserAccountControl: 0x822, Disabled: true}},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0", findings[0].Count)
	}
	if got, _ := findings[0].Details["passwordNotRequired"].(int); got != 0 {
		t.Errorf("Details[passwordNotRequired] = %v, want 0", findings[0].Details["passwordNotRequired"])
	}
}

// TestIA5Authenticator_EnabledFilter_ExcludesDisabledPasswordNotRequired
// guards the Enabled() filter on the passwordNotRequired count: without it,
// a disabled account would silently leak into the count. Literal 0x222
// (ACCOUNTDISABLE | NORMAL_ACCOUNT | PASSWD_NOTREQD, distinct from the
// detector's own uacPasswordNotRequired constant) paired with Disabled: true
// - types.User.Enabled() reads the Disabled bool field, not a
// UserAccountControl bit, so the fixture must set both to actually exercise
// the filter. The 0x220 witness (same bits minus ACCOUNTDISABLE, Disabled
// left false) is enabled and must still count.
func TestIA5Authenticator_EnabledFilter_ExcludesDisabledPasswordNotRequired(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
		Users: []types.User{
			{SAMAccountName: "disabled_ordinary", UserAccountControl: 0x222, Disabled: true},
			{SAMAccountName: "active_witness", UserAccountControl: 0x220},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1 - only the active witness violates", findings[0].Count)
	}
	if got, _ := findings[0].Details["passwordNotRequired"].(int); got != 1 {
		t.Errorf("Details[passwordNotRequired] = %v, want 1 - the disabled account must not be counted", findings[0].Details["passwordNotRequired"])
	}
}

// TestIA5Authenticator_MinPwdLength_BoundaryAt12 exercises the exact
// MinPwdLength boundary: 11 must still violate; 12, the compliant boundary
// itself, must not.
func TestIA5Authenticator_MinPwdLength_BoundaryAt12(t *testing.T) {
	cases := []struct {
		name      string
		minPwdLen int
		wantCount int
	}{
		{"11_below_boundary_violates", 11, 1},
		{"12_exact_boundary_compliant", 12, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewIA5AuthenticatorDetector()
			data := &audit.DetectorData{
				DomainInfo: &types.DomainInfo{MinPwdLength: tc.minPwdLen, MaxPwdAge: 0, PwdHistoryLength: 24},
			}
			findings := d.Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("MinPwdLength=%d: Count = %d, want %d", tc.minPwdLen, findings[0].Count, tc.wantCount)
			}
		})
	}
}

// TestIA5Authenticator_PwdHistoryLength_BoundaryAt24 exercises the exact
// PwdHistoryLength boundary from below: 23 must still violate; 24, the
// compliant boundary itself, must not.
func TestIA5Authenticator_PwdHistoryLength_BoundaryAt24(t *testing.T) {
	cases := []struct {
		name          string
		pwdHistoryLen int
		wantCount     int
	}{
		{"23_below_boundary_violates", 23, 1},
		{"24_exact_boundary_compliant", 24, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewIA5AuthenticatorDetector()
			data := &audit.DetectorData{
				DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: tc.pwdHistoryLen},
			}
			findings := d.Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("PwdHistoryLength=%d: Count = %d, want %d", tc.pwdHistoryLen, findings[0].Count, tc.wantCount)
			}
		})
	}
}

// TestIA5Authenticator_TrustAccountGuard_ExcludedFromBothCounts guards the
// trust-account exclusion against both counters at once, not just the one
// the earlier tests happened to check: a guard that moved between the
// passwordNeverExpires and passwordNotRequired increments would still pass
// a single-count assertion. Literal 0x10820 (INTERDOMAIN_TRUST_ACCOUNT | PASSWD_NOTREQD |
// DONT_EXPIRE_PASSWD) must land in neither count; the 0x10220 ordinary
// witness (same bits minus the trust flag, plus NORMAL_ACCOUNT) must land in
// both.
func TestIA5Authenticator_TrustAccountGuard_ExcludedFromBothCounts(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
		Users: []types.User{
			{SAMAccountName: "TRUST$", UserAccountControl: 0x10820},
			{SAMAccountName: "ordinary_svc", UserAccountControl: 0x10220},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if got, _ := findings[0].Details["passwordNeverExpires"].(int); got != 1 {
		t.Errorf("Details[passwordNeverExpires] = %v, want 1 - only the ordinary account counted, trust account excluded", findings[0].Details["passwordNeverExpires"])
	}
	if got, _ := findings[0].Details["passwordNotRequired"].(int); got != 1 {
		t.Errorf("Details[passwordNotRequired] = %v, want 1 - only the ordinary account counted, trust account excluded", findings[0].Details["passwordNotRequired"])
	}
}

// TestIA5Authenticator_DocMatchesFinding couples Title/Description in
// Detect() to Doc(), byte for byte, so a change to one without the other
// (or a stale docs_gen.go after a Description edit) is caught here rather
// than only by the catalog generator.
func TestIA5Authenticator_DocMatchesFinding(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	doc := d.Doc()
	if findings[0].Title != doc.Title {
		t.Errorf("Title = %q, Doc().Title = %q", findings[0].Title, doc.Title)
	}
	if findings[0].Description != doc.Description {
		t.Errorf("Description = %q, Doc().Description = %q", findings[0].Description, doc.Description)
	}
}
