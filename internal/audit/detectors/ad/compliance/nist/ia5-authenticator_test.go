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
		users = append(users, types.User{SAMAccountName: "svc", UserAccountControl: uacPasswordNeverExpires})
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
// at all) is untouched by the rotation-doctrine fix and still flags.
func TestIA5Authenticator_PasswordNotRequired_StillViolates(t *testing.T) {
	d := NewIA5AuthenticatorDetector()
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MinPwdLength: 14, MaxPwdAge: 0, PwdHistoryLength: 24},
		Users:      []types.User{{SAMAccountName: "nopass", UserAccountControl: uacPasswordNotRequired}},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1 - an account with no password required at all is a genuine authenticator-existence violation", findings[0].Count)
	}
}
