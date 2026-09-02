// Package audit — Bookings / first-party orphan accounts builder
// (v3.1.39 §2).
//
// Pure post-collection aggregator. Walks data.Users (already collected by
// GetUsers, with the v3.1.39 §2 addition of creationType to the $select)
// and produces audit.firstPartyAccounts — the cloud-only resource accounts
// the SaaS analyzer must render in the "Orphan accounts" Findings filter
// and against which it emits BOOKINGS_ORPHAN_ACCOUNT (UPN match) and
// FIRST_PARTY_RESOURCE_ACCOUNT (creationType match) findings.
//
// No Graph roundtrip — this is a pure derivation helper.

package audit

import (
	"regexp"
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// firstPartyPattern is one named UPN regex. The name is what appears in the
// audit JSON output as "matchPattern" so the SaaS analyzer can decide which
// finding to emit.
type firstPartyPattern struct {
	name string
	re   *regexp.Regexp
}

// firstPartyUPNPatterns is the list of regexes used to flag first-party /
// resource accounts by UPN. Frozen in the binary — Microsoft adds patterns
// rarely and a redeploy is acceptable.
//
// The first-match-wins ordering matters when an account satisfies multiple
// patterns: more specific patterns ("-bookings@") come before broader ones
// ("^bookings.*@") to keep the symbolic name informative.
var firstPartyUPNPatterns = []firstPartyPattern{
	{"bookings", regexp.MustCompile(`(?i)^bookings.*@`)},
	{"bookings", regexp.MustCompile(`(?i)-bookings@`)},
	{"forms", regexp.MustCompile(`(?i)^forms.*@`)},
	{"resource", regexp.MustCompile(`(?i)-resource@`)},
	{"app", regexp.MustCompile(`(?i)^app-`)},
	{"svc", regexp.MustCompile(`(?i)^svc-`)},
}

// firstPartyCreationTypes are the Microsoft creationType values that flag a
// user as first-party / resource. "" (empty) is included because Microsoft
// does not always populate the field on Bookings/Forms-created accounts.
var firstPartyCreationTypes = map[string]bool{
	"":                true,
	"Resource":        true,
	"EmailVerified":   true,
	"EmailUnverified": true,
}

// BuildFirstPartyAccountsSummary derives the cloud-only orphan account list
// from data.Users. Returns nil only when data is nil. Empty results return
// a populated summary (TotalDetected: 0, ByCreationType: {}) so the SaaS
// analyzer can distinguish "ran successfully, found nothing" from "didn't
// run at all".
func BuildFirstPartyAccountsSummary(data *DetectorData, version string) *types.FirstPartyAccountsSummary {
	if data == nil {
		return nil
	}

	summary := &types.FirstPartyAccountsSummary{
		ByCreationType:   map[string]int{},
		CollectorVersion: version,
	}

	for i := range data.Users {
		u := &data.Users[i]
		// Cloud-only filter: skip users that are AD-synced. Microsoft
		// returns onPremisesSyncEnabled=true on synced users, and nil
		// or false on cloud-only ones — we accept both as cloud-only.
		if u.AzureOnPremisesSyncEnabled != nil && *u.AzureOnPremisesSyncEnabled {
			continue
		}

		ct := derefString(u.AzureCreationType)
		ctMatches := firstPartyCreationTypes[ct]

		upn := strings.TrimSpace(u.UserPrincipalName)
		patternName := matchUPNPattern(upn)
		upnMatches := patternName != ""

		// Match logic: cloud-only AND (creationType in known set OR UPN
		// matches a regex). The "" creationType alone is too broad (it
		// would flag every regular cloud user), so we require UPN match
		// when the only signal is empty creationType.
		switch {
		case ct != "" && ctMatches:
			// real creationType signal — flag regardless of UPN
		case upnMatches:
			// UPN signal — flag regardless of creationType
		default:
			continue
		}

		entry := types.FirstPartyAccount{
			ID:                 u.ObjectSID, // Azure user object ID lives here
			UserPrincipalName:  u.UserPrincipalName,
			DisplayName:        u.DisplayName,
			CreationType:       ct,
			CreatedDateTime:    u.AzureCreatedDateTime,
			LastSignInDateTime: u.AzureLastSignInDateTime,
			AccountEnabled:     u.AzureAccountEnabled != nil && *u.AzureAccountEnabled,
			UserType:           derefString(u.AzureUserType),
			MatchPattern:       patternName,
		}
		summary.Accounts = append(summary.Accounts, entry)
		bumpCreationTypeBucket(summary.ByCreationType, ct)
	}

	summary.TotalDetected = len(summary.Accounts)

	// Deterministic order so audit JSON diffs across runs only reflect
	// real changes (additions / removals), not slice ordering jitter.
	sort.Slice(summary.Accounts, func(i, j int) bool {
		return summary.Accounts[i].UserPrincipalName < summary.Accounts[j].UserPrincipalName
	})

	return summary
}

// matchUPNPattern returns the symbolic name of the first regex that matches
// the UPN, or "" when none matches.
func matchUPNPattern(upn string) string {
	if upn == "" {
		return ""
	}
	for _, p := range firstPartyUPNPatterns {
		if p.re.MatchString(upn) {
			return p.name
		}
	}
	return ""
}

// bumpCreationTypeBucket increments the appropriate counter, falling back
// to "Other" for empty / unknown creationType values.
func bumpCreationTypeBucket(buckets map[string]int, ct string) {
	switch ct {
	case "Resource", "EmailVerified", "EmailUnverified":
		buckets[ct]++
	default:
		buckets["Other"]++
	}
}

// derefString returns *s, or "" when s is nil.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
