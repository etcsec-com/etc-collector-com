// Package audit — credential expiry derivation (v3.1.30 §7).
//
// Pure in-memory enrichment that runs after Azure data collection. Adds:
//   - per-credential AppCredentialStatus (daysUntilExpiry, bucket, isExpired)
//   - per-app/SP CredentialSummary rollup (counts per bucket, earliest expiry)
//   - tenant-wide CredentialEntityBucket aggregates (one for apps, one for SPs)
//
// No Graph calls, no I/O — derives everything from existing EndDate fields.
// Spares every consumer (SaaS analyzer, reports, dashboards, detectors)
// from re-implementing the same date arithmetic.
package audit

import (
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Bucket identifiers — also used as JSON values for AppCredentialStatus.Bucket
// and CredentialSummary.NearestExpiryBucket. Order from most to least urgent
// matches bucketPriority below.
const (
	BucketExpired     = "expired"
	BucketExpiring7d  = "expiring_7d"
	BucketExpiring30d = "expiring_30d"
	BucketExpiring60d = "expiring_60d"
	BucketExpiring90d = "expiring_90d"
	BucketValid       = "valid"
	BucketUnknown     = "unknown"
)

// bucketPriority — lower = more urgent. Used to derive NearestExpiryBucket
// from a slice of credential statuses.
var bucketPriority = map[string]int{
	BucketExpired:     0,
	BucketExpiring7d:  1,
	BucketExpiring30d: 2,
	BucketExpiring60d: 3,
	BucketExpiring90d: 4,
	BucketValid:       5,
	BucketUnknown:     6,
}

// ComputeCredentialStatus derives the expiry view of a single credential.
// Pure: deterministic for a given (endDate, now). A zero endDate yields the
// "unknown" bucket — caller doesn't have to special-case missing dates.
func ComputeCredentialStatus(endDate, now time.Time) *types.AppCredentialStatus {
	status := &types.AppCredentialStatus{
		ComputedAt: now,
	}

	if endDate.IsZero() {
		status.Bucket = BucketUnknown
		return status
	}

	// Integer day arithmetic — truncate sub-day deltas so a cred expiring in
	// 30 days and 1 hour still lands in the 30d bucket.
	deltaHours := endDate.Sub(now).Hours()
	days := int(deltaHours / 24)

	status.DaysUntilExpiry = days

	switch {
	case days < 0:
		status.Bucket = BucketExpired
		status.IsExpired = true
	case days <= 7:
		status.Bucket = BucketExpiring7d
	case days <= 30:
		status.Bucket = BucketExpiring30d
	case days <= 60:
		status.Bucket = BucketExpiring60d
	case days <= 90:
		status.Bucket = BucketExpiring90d
	default:
		status.Bucket = BucketValid
	}

	return status
}

// summarizeCreds walks both password+key credential slices, mutates each cred
// to add CredentialStatus, and returns the per-entity rollup. Returns nil if
// there are zero credentials.
func summarizeCreds(passwords, keys []types.AppCredential, now time.Time) *types.CredentialSummary {
	total := len(passwords) + len(keys)
	if total == 0 {
		return nil
	}

	summary := &types.CredentialSummary{
		TotalCredentials: total,
	}

	process := func(creds []types.AppCredential) {
		for i := range creds {
			cred := &creds[i]
			status := ComputeCredentialStatus(cred.EndDate, now)
			cred.CredentialStatus = status

			switch status.Bucket {
			case BucketExpired:
				summary.ExpiredCount++
			case BucketExpiring7d:
				summary.Expiring7dCount++
			case BucketExpiring30d:
				summary.Expiring30dCount++
			case BucketExpiring60d:
				summary.Expiring60dCount++
			case BucketExpiring90d:
				summary.Expiring90dCount++
			case BucketValid:
				summary.ValidCount++
			case BucketUnknown:
				summary.UnknownCount++
			}

			if !cred.EndDate.IsZero() {
				if summary.EarliestExpiry == nil || cred.EndDate.Before(*summary.EarliestExpiry) {
					end := cred.EndDate
					summary.EarliestExpiry = &end
				}
				if !status.IsExpired {
					if summary.EarliestNonExpiredExpiry == nil || cred.EndDate.Before(*summary.EarliestNonExpiredExpiry) {
						end := cred.EndDate
						summary.EarliestNonExpiredExpiry = &end
					}
				}
			}
		}
	}

	process(passwords)
	process(keys)

	summary.NearestExpiryBucket = pickNearestBucket(summary)
	return summary
}

// pickNearestBucket returns the most-urgent bucket present in the summary
// (lowest bucketPriority with count > 0). Returns "" if the only credentials
// are unknown — the SaaS treats empty as "no actionable urgency".
func pickNearestBucket(s *types.CredentialSummary) string {
	candidates := []struct {
		name  string
		count int
	}{
		{BucketExpired, s.ExpiredCount},
		{BucketExpiring7d, s.Expiring7dCount},
		{BucketExpiring30d, s.Expiring30dCount},
		{BucketExpiring60d, s.Expiring60dCount},
		{BucketExpiring90d, s.Expiring90dCount},
		{BucketValid, s.ValidCount},
	}
	for _, c := range candidates {
		if c.count > 0 {
			return c.name
		}
	}
	return ""
}

// EnrichApplications walks every AppRegistration, mutates its credentials to
// add CredentialStatus, attaches a per-app CredentialSummary, and returns the
// tenant-wide bucket. Mute the slice in place — caller doesn't need to
// reassign. Returns nil if there are zero apps.
func EnrichApplications(apps []types.AppRegistration, now time.Time) *types.CredentialEntityBucket {
	if len(apps) == 0 {
		return nil
	}
	bucket := &types.CredentialEntityBucket{
		TotalEntities: len(apps),
	}
	for i := range apps {
		app := &apps[i]
		summary := summarizeCreds(app.PasswordCredentials, app.KeyCredentials, now)
		app.CredentialSummary = summary
		accumulateEntity(bucket, summary)
	}
	return bucket
}

// EnrichServicePrincipals — mirror of EnrichApplications for SPs.
func EnrichServicePrincipals(sps []types.ServicePrincipal, now time.Time) *types.CredentialEntityBucket {
	if len(sps) == 0 {
		return nil
	}
	bucket := &types.CredentialEntityBucket{
		TotalEntities: len(sps),
	}
	for i := range sps {
		sp := &sps[i]
		summary := summarizeCreds(sp.PasswordCredentials, sp.KeyCredentials, now)
		sp.CredentialSummary = summary
		accumulateEntity(bucket, summary)
	}
	return bucket
}

// accumulateEntity counts an entity once per bucket it touches. Buckets are
// inclusive — an entity with both an expired cred and a 60-day-out cred
// increments both EntitiesWithExpired and EntitiesExpiring60d. The SaaS
// dashboard groups by NearestExpiryBucket per entity for cliff visualisation.
func accumulateEntity(bucket *types.CredentialEntityBucket, summary *types.CredentialSummary) {
	if summary == nil {
		return
	}
	if summary.ExpiredCount > 0 {
		bucket.EntitiesWithExpired++
	}
	if summary.Expiring7dCount > 0 {
		bucket.EntitiesExpiring7d++
	}
	if summary.Expiring30dCount > 0 {
		bucket.EntitiesExpiring30d++
	}
	if summary.Expiring60dCount > 0 {
		bucket.EntitiesExpiring60d++
	}
	if summary.Expiring90dCount > 0 {
		bucket.EntitiesExpiring90d++
	}
}

// BuildCredentialExpirySummary composes the two entity buckets into the
// tenant-wide payload that lands at audit.summary.credentialExpiry. Returns
// nil when neither bucket has any entities — keeps the JSON clean on tenants
// without apps or SPs.
func BuildCredentialExpirySummary(appsBucket, spsBucket *types.CredentialEntityBucket) *types.CredentialExpirySummary {
	if appsBucket == nil && spsBucket == nil {
		return nil
	}
	return &types.CredentialExpirySummary{
		Applications:      appsBucket,
		ServicePrincipals: spsBucket,
	}
}
