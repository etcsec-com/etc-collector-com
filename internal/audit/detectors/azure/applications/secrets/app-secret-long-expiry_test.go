package secrets

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAppSecretLongExpiry_DoesNotOverattributeSixMonths locks in a correction:
// Microsoft's own guidance (learn.microsoft.com/en-us/entra/
// identity-platform/how-to-add-credentials) says "less than 12 months", not
// "6 months preferred". The description must not attribute the specific
// 6-month threshold to Microsoft.
func TestAppSecretLongExpiry_DoesNotOverattributeSixMonths(t *testing.T) {
	d := NewAppSecretLongExpiryDetector()
	f := d.Detect(context.Background(), &audit.DetectorData{Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})[0]

	if strings.Contains(f.Description, "6 months preferred") {
		t.Errorf("description must not attribute a specific '6 months preferred' figure to Microsoft, got %q", f.Description)
	}
}

// TestAppSecretLongExpiry_ThresholdMatchesRecommendation reproduces the
// contradiction between what this detector announces (secrets should expire
// well under 12 months, 6 preferred) and what it used to check for (only
// flagging secrets valid past the platform's 2-year hard cap, which Entra
// itself never lets you exceed - a threshold that could never fire).
//
// Before the fix: an app with a secret valid for 8 months (well beyond the
// recommended window, but under the old 2-year threshold) wrongly passed.
// After the fix it is caught, while a legitimate long-lived secret (3 years,
// impossible in practice but exercises the "still triggers" boundary) and a
// genuinely short-lived one keep behaving as expected.
func TestAppSecretLongExpiry_ThresholdMatchesRecommendation(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	eightMonthSecret := types.AppRegistration{
		ID:          "11111111-1111-1111-1111-111111111111",
		DisplayName: "eight-month-secret-app",
		PasswordCredentials: []types.AppCredential{
			{KeyID: "k1", StartDate: now, EndDate: now.AddDate(0, 8, 0)},
		},
	}
	threeYearSecret := types.AppRegistration{
		ID:          "22222222-2222-2222-2222-222222222222",
		DisplayName: "three-year-secret-app",
		PasswordCredentials: []types.AppCredential{
			{KeyID: "k2", StartDate: now, EndDate: now.AddDate(3, 0, 0)},
		},
	}
	threeMonthSecret := types.AppRegistration{
		ID:          "33333333-3333-3333-3333-333333333333",
		DisplayName: "three-month-secret-app",
		PasswordCredentials: []types.AppCredential{
			{KeyID: "k3", StartDate: now, EndDate: now.AddDate(0, 3, 0)},
		},
	}

	d := NewAppSecretLongExpiryDetector()
	data := &audit.DetectorData{
		Now:                   now,
		AzureAppRegistrations: []types.AppRegistration{eightMonthSecret, threeYearSecret, threeMonthSecret},
		IncludeDetails:        true,
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("expected 2 apps flagged (8-month and 3-year secrets), got %d", f.Count)
	}

	flagged := map[string]bool{}
	for _, e := range f.AffectedEntities {
		flagged[e.DisplayName] = true
	}
	if !flagged["eight-month-secret-app"] {
		t.Error("8-month secret should now be flagged (previously wrongly passed under the 2-year threshold)")
	}
	if !flagged["three-year-secret-app"] {
		t.Error("3-year secret must still be flagged")
	}
	if flagged["three-month-secret-app"] {
		t.Error("3-month secret is within the recommended window and must not be flagged")
	}
}
