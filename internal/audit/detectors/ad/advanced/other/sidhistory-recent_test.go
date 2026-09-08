package other

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestSIDHistoryRecent_DescriptionDoesNotClaimAttributeLevelPrecision pins
// the honesty fix: the old Description said "SIDHistory attribute ... were
// recently modified" / "SIDHistory changes can indicate...", implying the
// detector knows sIDHistory itself changed. It only ever reads whenChanged
// (object-level, any attribute), so the claim was false precision. This
// asserts the old wording is gone and the accurate wording is present.
func TestSIDHistoryRecent_DescriptionDoesNotClaimAttributeLevelPrecision(t *testing.T) {
	findings := NewSIDHistoryRecentDetector().Detect(context.Background(), &audit.DetectorData{Now: time.Now()})
	desc := findings[0].Description

	if strings.Contains(desc, "SIDHistory changes can indicate") {
		t.Fatalf("Description still implies SIDHistory itself was observed changing: %q", desc)
	}
	if !strings.Contains(desc, "whenChanged") || !strings.Contains(desc, "ANY attribute change") {
		t.Fatalf("Description must honestly say whenChanged is an any-attribute proxy, got: %q", desc)
	}
	if !strings.Contains(desc, "Computer objects are not evaluated") {
		t.Fatalf("Description must disclose the users-only coverage limitation, got: %q", desc)
	}
}

// TestSIDHistoryRecent_UnrelatedEditAlsoMatchesProxy documents (as an
// executable pin, not just prose) exactly what the whenChanged proxy really
// measures: a user with old, stable sIDHistory that receives ANY unrelated
// attribute edit still matches, because AD exposes no per-attribute
// modification timestamp for sIDHistory over LDAP. This is the known,
// accepted limitation the description above now discloses - not a bug.
func TestSIDHistoryRecent_UnrelatedEditAlsoMatchesProxy(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:             "CN=migrated,OU=Users,DC=contoso,DC=com",
				SAMAccountName: "migrated",
				SIDHistory:     []string{"S-1-5-21-1-2-3-1111"}, // long-stable, unrelated to the recent edit
				WhenChanged:    now.AddDate(0, 0, -1),           // "recent" only because of e.g. a phone-number edit
			},
		},
	}

	findings := NewSIDHistoryRecentDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("expected the whenChanged proxy to match an unrelated recent edit, got Count=%d", findings[0].Count)
	}
}
