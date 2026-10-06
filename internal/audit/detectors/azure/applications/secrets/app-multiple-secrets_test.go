package secrets

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAppMultipleSecrets_MeasuresConcurrentActiveCount locks in what this
// detector actually measures - more than 2 password credentials active at
// the same time - now that the description no longer presents "max 2 active
// secrets" as an official Microsoft rule (it was never sourced as one).
func TestAppMultipleSecrets_MeasuresConcurrentActiveCount(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	twoActive := types.AppRegistration{
		ID:          "11111111-1111-1111-1111-111111111111",
		DisplayName: "two-active-app",
		PasswordCredentials: []types.AppCredential{
			{KeyID: "a", StartDate: now.AddDate(0, -1, 0), EndDate: now.AddDate(0, 1, 0)},
			{KeyID: "b", StartDate: now.AddDate(0, -1, 0), EndDate: now.AddDate(0, 2, 0)},
			{KeyID: "c-expired", StartDate: now.AddDate(-1, 0, 0), EndDate: now.AddDate(0, -1, 0)},
		},
	}
	threeActive := types.AppRegistration{
		ID:          "22222222-2222-2222-2222-222222222222",
		DisplayName: "three-active-app",
		PasswordCredentials: []types.AppCredential{
			{KeyID: "a", StartDate: now.AddDate(0, -1, 0), EndDate: now.AddDate(0, 1, 0)},
			{KeyID: "b", StartDate: now.AddDate(0, -1, 0), EndDate: now.AddDate(0, 2, 0)},
			{KeyID: "c", StartDate: now.AddDate(0, -1, 0), EndDate: now.AddDate(0, 3, 0)},
		},
	}

	d := NewAppMultipleSecretsDetector()
	data := &audit.DetectorData{
		Now:                   now,
		AzureAppRegistrations: []types.AppRegistration{twoActive, threeActive},
		IncludeDetails:        true,
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected only the 3-active-secret app flagged, got count %d", f.Count)
	}
	if f.AffectedEntities[0].DisplayName != "three-active-app" {
		t.Errorf("expected three-active-app flagged, got %q", f.AffectedEntities[0].DisplayName)
	}
	if strings.Contains(f.Description, "Microsoft") {
		t.Error("description must not attribute the 2-secret threshold to Microsoft; it is a local heuristic, not a sourced rule")
	}
}
