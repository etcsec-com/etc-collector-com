package audit

import (
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestComputeCredentialStatus(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		endDate     time.Time
		wantBucket  string
		wantExpired bool
		wantDays    int
	}{
		{
			name:       "zero endDate -> unknown",
			endDate:    time.Time{},
			wantBucket: BucketUnknown,
		},
		{
			name:        "expired by 5 days",
			endDate:     now.Add(-5 * 24 * time.Hour),
			wantBucket:  BucketExpired,
			wantExpired: true,
			wantDays:    -5,
		},
		{
			name:       "expiring in 3 days -> 7d bucket",
			endDate:    now.Add(3 * 24 * time.Hour),
			wantBucket: BucketExpiring7d,
			wantDays:   3,
		},
		{
			name:       "expiring in exactly 7 days -> 7d bucket",
			endDate:    now.Add(7 * 24 * time.Hour),
			wantBucket: BucketExpiring7d,
			wantDays:   7,
		},
		{
			name:       "expiring in 8 days -> 30d bucket",
			endDate:    now.Add(8 * 24 * time.Hour),
			wantBucket: BucketExpiring30d,
			wantDays:   8,
		},
		{
			name:       "expiring in 30 days -> 30d bucket",
			endDate:    now.Add(30 * 24 * time.Hour),
			wantBucket: BucketExpiring30d,
			wantDays:   30,
		},
		{
			name:       "expiring in 45 days -> 60d bucket",
			endDate:    now.Add(45 * 24 * time.Hour),
			wantBucket: BucketExpiring60d,
			wantDays:   45,
		},
		{
			name:       "expiring in 75 days -> 90d bucket",
			endDate:    now.Add(75 * 24 * time.Hour),
			wantBucket: BucketExpiring90d,
			wantDays:   75,
		},
		{
			name:       "expiring in 200 days -> valid",
			endDate:    now.Add(200 * 24 * time.Hour),
			wantBucket: BucketValid,
			wantDays:   200,
		},
		{
			name:       "expiring in 30 days + 1 hour -> still 30d bucket (truncates)",
			endDate:    now.Add(30*24*time.Hour + 1*time.Hour),
			wantBucket: BucketExpiring30d,
			wantDays:   30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeCredentialStatus(tt.endDate, now)
			if got == nil {
				t.Fatalf("expected non-nil status")
			}
			if got.Bucket != tt.wantBucket {
				t.Errorf("Bucket = %q, want %q", got.Bucket, tt.wantBucket)
			}
			if got.IsExpired != tt.wantExpired {
				t.Errorf("IsExpired = %v, want %v", got.IsExpired, tt.wantExpired)
			}
			if !tt.endDate.IsZero() && got.DaysUntilExpiry != tt.wantDays {
				t.Errorf("DaysUntilExpiry = %d, want %d", got.DaysUntilExpiry, tt.wantDays)
			}
			if got.ComputedAt != now {
				t.Errorf("ComputedAt = %v, want %v", got.ComputedAt, now)
			}
		})
	}
}

func TestEnrichApplications_NearestExpiryBucketPriority(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	apps := []types.AppRegistration{
		{
			DisplayName: "app-mixed",
			PasswordCredentials: []types.AppCredential{
				{KeyID: "p1", EndDate: now.Add(-10 * 24 * time.Hour)}, // expired
				{KeyID: "p2", EndDate: now.Add(45 * 24 * time.Hour)},  // 60d
				{KeyID: "p3", EndDate: now.Add(200 * 24 * time.Hour)}, // valid
			},
		},
		{
			DisplayName: "app-only-90d",
			PasswordCredentials: []types.AppCredential{
				{KeyID: "p4", EndDate: now.Add(80 * 24 * time.Hour)},
			},
		},
		{
			DisplayName: "app-no-creds",
		},
	}

	bucket := EnrichApplications(apps, now)
	if bucket == nil {
		t.Fatal("expected non-nil bucket")
	}
	if bucket.TotalEntities != 3 {
		t.Errorf("TotalEntities = %d, want 3", bucket.TotalEntities)
	}
	if bucket.EntitiesWithExpired != 1 {
		t.Errorf("EntitiesWithExpired = %d, want 1", bucket.EntitiesWithExpired)
	}
	if bucket.EntitiesExpiring60d != 1 {
		t.Errorf("EntitiesExpiring60d = %d, want 1", bucket.EntitiesExpiring60d)
	}
	if bucket.EntitiesExpiring90d != 1 {
		t.Errorf("EntitiesExpiring90d = %d, want 1", bucket.EntitiesExpiring90d)
	}

	mixed := apps[0]
	if mixed.CredentialSummary == nil {
		t.Fatal("app-mixed: expected CredentialSummary")
	}
	if mixed.CredentialSummary.NearestExpiryBucket != BucketExpired {
		t.Errorf("app-mixed nearest = %q, want %q", mixed.CredentialSummary.NearestExpiryBucket, BucketExpired)
	}
	if mixed.CredentialSummary.ExpiredCount != 1 || mixed.CredentialSummary.Expiring60dCount != 1 || mixed.CredentialSummary.ValidCount != 1 {
		t.Errorf("app-mixed counts wrong: %+v", mixed.CredentialSummary)
	}
	if mixed.CredentialSummary.EarliestExpiry == nil {
		t.Fatal("app-mixed: expected EarliestExpiry")
	}
	if !mixed.CredentialSummary.EarliestExpiry.Equal(now.Add(-10 * 24 * time.Hour)) {
		t.Errorf("app-mixed EarliestExpiry = %v, want %v", *mixed.CredentialSummary.EarliestExpiry, now.Add(-10*24*time.Hour))
	}
	if mixed.CredentialSummary.EarliestNonExpiredExpiry == nil {
		t.Fatal("app-mixed: expected EarliestNonExpiredExpiry")
	}
	if !mixed.CredentialSummary.EarliestNonExpiredExpiry.Equal(now.Add(45 * 24 * time.Hour)) {
		t.Errorf("app-mixed EarliestNonExpiredExpiry = %v, want %v", *mixed.CredentialSummary.EarliestNonExpiredExpiry, now.Add(45*24*time.Hour))
	}

	// Verify per-credential mutation took effect.
	if apps[0].PasswordCredentials[0].CredentialStatus == nil {
		t.Fatal("expected per-credential CredentialStatus to be populated")
	}
	if !apps[0].PasswordCredentials[0].CredentialStatus.IsExpired {
		t.Error("first cred should be marked expired")
	}

	if apps[2].CredentialSummary != nil {
		t.Error("app-no-creds should have nil CredentialSummary")
	}
}

func TestEnrichServicePrincipals_KeysAndPasswords(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	sps := []types.ServicePrincipal{
		{
			DisplayName: "sp-with-cert",
			KeyCredentials: []types.AppCredential{
				{KeyID: "k1", Type: "certificate", EndDate: now.Add(5 * 24 * time.Hour)},
			},
			PasswordCredentials: []types.AppCredential{
				{KeyID: "p1", Type: "password", EndDate: now.Add(20 * 24 * time.Hour)},
			},
		},
	}

	bucket := EnrichServicePrincipals(sps, now)
	if bucket == nil || bucket.TotalEntities != 1 {
		t.Fatalf("bucket = %+v", bucket)
	}
	if bucket.EntitiesExpiring7d != 1 || bucket.EntitiesExpiring30d != 1 {
		t.Errorf("bucket counts wrong: %+v", bucket)
	}
	if sps[0].CredentialSummary.TotalCredentials != 2 {
		t.Errorf("TotalCredentials = %d, want 2", sps[0].CredentialSummary.TotalCredentials)
	}
	if sps[0].CredentialSummary.NearestExpiryBucket != BucketExpiring7d {
		t.Errorf("nearest = %q, want %q", sps[0].CredentialSummary.NearestExpiryBucket, BucketExpiring7d)
	}
}

func TestEnrich_EmptyInput(t *testing.T) {
	now := time.Now()
	if got := EnrichApplications(nil, now); got != nil {
		t.Errorf("EnrichApplications(nil) = %+v, want nil", got)
	}
	if got := EnrichServicePrincipals(nil, now); got != nil {
		t.Errorf("EnrichServicePrincipals(nil) = %+v, want nil", got)
	}
}

func TestBuildCredentialExpirySummary(t *testing.T) {
	if got := BuildCredentialExpirySummary(nil, nil); got != nil {
		t.Errorf("both-nil should return nil, got %+v", got)
	}
	apps := &types.CredentialEntityBucket{TotalEntities: 5}
	got := BuildCredentialExpirySummary(apps, nil)
	if got == nil || got.Applications != apps || got.ServicePrincipals != nil {
		t.Errorf("apps-only build wrong: %+v", got)
	}
}
