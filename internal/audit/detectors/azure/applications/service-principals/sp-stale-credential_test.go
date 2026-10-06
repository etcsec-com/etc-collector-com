package serviceprincipals

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestSPStaleCredential_CoversCertificatesToo reproduces the coverage gap:
// the title promises "Stale Credentials" but the check only ever looked at
// PasswordCredentials, never KeyCredentials (certificates). Before the fix,
// an SP whose only credential is a stale certificate wrongly passed. A
// legitimate stale-password case must keep triggering.
func TestSPStaleCredential_CoversCertificatesToo(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	twoYearsAgo := now.AddDate(-2, 0, 0)

	staleCertOnly := types.ServicePrincipal{
		ID:          "11111111-1111-1111-1111-111111111111",
		DisplayName: "stale-cert-sp",
		KeyCredentials: []types.AppCredential{
			{KeyID: "cert1", StartDate: twoYearsAgo, EndDate: now.AddDate(1, 0, 0)},
		},
	}
	staleSecretOnly := types.ServicePrincipal{
		ID:          "22222222-2222-2222-2222-222222222222",
		DisplayName: "stale-secret-sp",
		PasswordCredentials: []types.AppCredential{
			{KeyID: "secret1", StartDate: twoYearsAgo, EndDate: now.AddDate(1, 0, 0)},
		},
	}
	freshOnly := types.ServicePrincipal{
		ID:          "33333333-3333-3333-3333-333333333333",
		DisplayName: "fresh-sp",
		PasswordCredentials: []types.AppCredential{
			{KeyID: "secret1", StartDate: now.AddDate(0, -1, 0), EndDate: now.AddDate(1, 0, 0)},
		},
		KeyCredentials: []types.AppCredential{
			{KeyID: "cert1", StartDate: now.AddDate(0, -1, 0), EndDate: now.AddDate(1, 0, 0)},
		},
	}

	d := NewSPStaleCredentialDetector()
	data := &audit.DetectorData{
		Now:                    now,
		AzureServicePrincipals: []types.ServicePrincipal{staleCertOnly, staleSecretOnly, freshOnly},
		IncludeDetails:         true,
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("expected 2 SPs flagged (stale cert + stale secret), got %d", f.Count)
	}

	flagged := map[string]bool{}
	for _, e := range f.AffectedEntities {
		flagged[e.DisplayName] = true
	}
	if !flagged["stale-cert-sp"] {
		t.Error("SP with only a stale certificate should now be flagged (previously wrongly passed, certs were never checked)")
	}
	if !flagged["stale-secret-sp"] {
		t.Error("SP with a stale password credential must still be flagged")
	}
	if flagged["fresh-sp"] {
		t.Error("SP with only fresh credentials must not be flagged")
	}
}

// TestSPStaleCredential_CertUsesShorterThreshold reproduces the ecart:
// Microsoft's recommended maximum lifetime for a certificate is 180 days
// (vs. under 12 months for a secret) - see the source citation on
// certStaleAfter. Before the fix, both credential types shared one 1-year
// threshold, so a certificate active for 200 days - already well past
// Microsoft's 180-day recommendation - wrongly passed as fresh.
func TestSPStaleCredential_CertUsesShorterThreshold(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	certPast180Days := types.ServicePrincipal{
		ID:          "44444444-4444-4444-4444-444444444444",
		DisplayName: "cert-200-days-sp",
		KeyCredentials: []types.AppCredential{
			{KeyID: "cert1", StartDate: now.AddDate(0, 0, -200), EndDate: now.AddDate(1, 0, 0)},
		},
	}
	certUnder180Days := types.ServicePrincipal{
		ID:          "55555555-5555-5555-5555-555555555555",
		DisplayName: "cert-100-days-sp",
		KeyCredentials: []types.AppCredential{
			{KeyID: "cert1", StartDate: now.AddDate(0, 0, -100), EndDate: now.AddDate(1, 0, 0)},
		},
	}

	d := NewSPStaleCredentialDetector()
	data := &audit.DetectorData{
		Now:                    now,
		AzureServicePrincipals: []types.ServicePrincipal{certPast180Days, certUnder180Days},
		IncludeDetails:         true,
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 SP flagged (cert past 180 days), got %d", f.Count)
	}

	flagged := map[string]bool{}
	for _, e := range f.AffectedEntities {
		flagged[e.DisplayName] = true
	}
	if !flagged["cert-200-days-sp"] {
		t.Error("SP with a certificate active 200 days should be flagged: past Microsoft's 180-day recommended maximum")
	}
	if flagged["cert-100-days-sp"] {
		t.Error("SP with a certificate active only 100 days must not be flagged: under both the 180-day and 1-year thresholds")
	}
}
