package secrets

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAppNoCredentialRotation_DoesNotOverattributeSixMonths locks in a
// Microsoft's stated guidance is "less than 12 months",
// not "6 months preferred" - the description must not attribute that
// specific figure to Microsoft.
func TestAppNoCredentialRotation_DoesNotOverattributeSixMonths(t *testing.T) {
	d := NewAppNoCredentialRotationDetector()
	f := d.Detect(context.Background(), &audit.DetectorData{Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})[0]

	if strings.Contains(f.Description, "6 months preferred") {
		t.Errorf("description must not attribute a specific '6 months preferred' figure to Microsoft, got %q", f.Description)
	}
}

// TestAppNoCredentialRotation_TitleMatchesYearlyMeasurement locks in the
// renamed title/description: this detector only ever measures "no new
// credential introduced in the past 12 months" - it does not verify a
// 90-180 day rotation cadence, so it must not claim to.
func TestAppNoCredentialRotation_TitleMatchesYearlyMeasurement(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	rotatedRecently := types.AppRegistration{
		ID:          "11111111-1111-1111-1111-111111111111",
		DisplayName: "rotated-recently-app",
		PasswordCredentials: []types.AppCredential{
			{KeyID: "old", StartDate: now.AddDate(-2, 0, 0), EndDate: now.AddDate(1, 0, 0)},
			{KeyID: "new", StartDate: now.AddDate(0, -2, 0), EndDate: now.AddDate(2, 0, 0)},
		},
	}
	neverRotated := types.AppRegistration{
		ID:          "22222222-2222-2222-2222-222222222222",
		DisplayName: "never-rotated-app",
		PasswordCredentials: []types.AppCredential{
			{KeyID: "old", StartDate: now.AddDate(-2, 0, 0), EndDate: now.AddDate(1, 0, 0)},
		},
	}

	d := NewAppNoCredentialRotationDetector()
	data := &audit.DetectorData{
		Now:                   now,
		AzureAppRegistrations: []types.AppRegistration{rotatedRecently, neverRotated},
		IncludeDetails:        true,
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected only the never-rotated app flagged, got count %d", f.Count)
	}
	if f.AffectedEntities[0].DisplayName != "never-rotated-app" {
		t.Errorf("expected never-rotated-app flagged, got %q", f.AffectedEntities[0].DisplayName)
	}
	if f.Title != "No Credential Rotation in Over a Year" {
		t.Errorf("title must state exactly what is measured, got %q", f.Title)
	}
}
