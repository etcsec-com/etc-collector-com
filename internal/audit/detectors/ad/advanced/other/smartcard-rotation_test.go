package other

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func smartcardUser(passwordLastSet time.Time) types.User {
	return types.User{
		DN:                 "CN=scuser,OU=Users,DC=contoso,DC=com",
		SAMAccountName:     "scuser",
		UserAccountControl: smartcardRequiredFlag,
		PasswordLastSet:    passwordLastSet,
	}
}

// TestSmartcardRotation_DomainKnobDisabledFiresRegardlessOfRecentPasswordSet
// pins the real bug: the old code inferred "rotation disabled" purely from
// pwdLastSet staleness (>90 days), so a smart-card account whose password
// was set an hour ago never fired even though the domain has never enabled
// msDS-ExpirePasswordsOnSmartCardOnlyAccounts - i.e. AD will NEVER rotate
// this password again, by design, no matter how "fresh" it looks today.
// This must fail against the old staleness-only logic and pass now that the
// real domain-level control is read.
func TestSmartcardRotation_DomainKnobDisabledFiresRegardlessOfRecentPasswordSet(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		DomainInfo: &types.DomainInfo{
			DomainDN: "DC=contoso,DC=com",
			// ExpirePasswordsOnSmartCardOnlyAccounts left false (default: not enabled).
			MaxPasswordAge: 42,
		},
		Users: []types.User{smartcardUser(now.Add(-1 * time.Hour))}, // set an hour ago
	}

	findings := NewSmartcardRotationDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 - domain never enabled the rotation knob, so this password is never rotated by design regardless of pwdLastSet recency; got %d", findings[0].Count)
	}
}

// TestSmartcardRotation_DomainKnobEnabledStaleAgainstRealPolicyFires: once
// the domain has enabled rotation, staleness is judged against the domain's
// REAL maxPwdAge (here 30 days), not an invented flat constant.
func TestSmartcardRotation_DomainKnobEnabledStaleAgainstRealPolicyFires(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		DomainInfo: &types.DomainInfo{
			DomainDN:                               "DC=contoso,DC=com",
			ExpirePasswordsOnSmartCardOnlyAccounts: true,
			MaxPasswordAge:                         30,
		},
		Users: []types.User{smartcardUser(now.AddDate(0, 0, -45))}, // 45 days ago, policy is 30
	}

	findings := NewSmartcardRotationDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 - 45 days exceeds the domain's real 30-day maxPwdAge, got %d", findings[0].Count)
	}
}

// TestSmartcardRotation_DomainKnobEnabledFreshDoesNotFire: within the real
// policy window, no finding.
func TestSmartcardRotation_DomainKnobEnabledFreshDoesNotFire(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		DomainInfo: &types.DomainInfo{
			DomainDN:                               "DC=contoso,DC=com",
			ExpirePasswordsOnSmartCardOnlyAccounts: true,
			MaxPasswordAge:                         30,
		},
		Users: []types.User{smartcardUser(now.AddDate(0, 0, -10))}, // 10 days ago, policy is 30
	}

	findings := NewSmartcardRotationDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 - 10 days is within the domain's real 30-day maxPwdAge, got %d", findings[0].Count)
	}
}

// TestSmartcardRotation_NoDomainInfoDoesNotFire: DomainInfo wasn't measured
// at all - must not punish a client we couldn't query.
func TestSmartcardRotation_NoDomainInfoDoesNotFire(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now:   now,
		Users: []types.User{smartcardUser(now.AddDate(0, 0, -365))},
	}

	findings := NewSmartcardRotationDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 when domain policy was never measured, got %d", findings[0].Count)
	}
}

// TestSmartcardRotation_KnobEnabledNoMaxPwdAgeDoesNotInventThreshold: the
// domain has enabled rotation but has "passwords never expire" (maxPwdAge
// 0) - there is no real schedule to compare against, so nothing is
// inferred rather than falling back to a made-up day count.
func TestSmartcardRotation_KnobEnabledNoMaxPwdAgeDoesNotInventThreshold(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		DomainInfo: &types.DomainInfo{
			DomainDN:                               "DC=contoso,DC=com",
			ExpirePasswordsOnSmartCardOnlyAccounts: true,
			MaxPasswordAge:                         0,
		},
		Users: []types.User{smartcardUser(now.AddDate(0, 0, -365))},
	}

	findings := NewSmartcardRotationDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 - no real policy threshold to compare against, got %d", findings[0].Count)
	}
}
