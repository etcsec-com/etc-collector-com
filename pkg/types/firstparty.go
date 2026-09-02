package types

import "time"

// === v3.1.39 §2 — Bookings / first-party orphan accounts ===
//
// Microsoft Bookings, Forms, Lists and various first-party apps create
// resource accounts on first use. They show up in /users but have no human
// owner — typical access reviews skip them and they become silent escalation
// surface (auth via the bound service principal). The collector surfaces them
// at audit.firstPartyAccounts so the SaaS analyzer can emit
//   BOOKINGS_ORPHAN_ACCOUNT       (UPN matched the bookings/forms/svc/app/etc. pattern)
//   FIRST_PARTY_RESOURCE_ACCOUNT  (creationType = Resource)
//
// Match logic (see internal/audit/firstparty.go):
//   onPremisesSyncEnabled != true  AND
//   (creationType in {Resource, EmailVerified, EmailUnverified, ""}
//    OR UPN matches one of the firstPartyUPNPatterns)
//
// Volume is small (<20 entries on a typical tenant), so we ship the full
// list — no cap.

// FirstPartyAccountsSummary is the audit.firstPartyAccounts payload.
type FirstPartyAccountsSummary struct {
	// TotalDetected is the count of cloud-only users matching the
	// detection rule. Always populated, even when zero.
	TotalDetected int `json:"totalDetected"`

	// ByCreationType buckets the matched accounts. Keys we use:
	//   "Resource", "EmailVerified", "EmailUnverified", "Other"
	// "Other" covers creationType == "" or unknown values, typically the
	// Bookings/Forms accounts that match by UPN pattern only.
	ByCreationType map[string]int `json:"byCreationType"`

	// Accounts is the full list of matched accounts, sorted by UPN for
	// deterministic diffs across audits.
	Accounts []FirstPartyAccount `json:"accounts,omitempty"`

	// CollectorVersion is the binary version that built this rollup —
	// lets the SaaS trace a summary back to the exact helper logic.
	CollectorVersion string `json:"collectorVersion"`
}

// FirstPartyAccount is one orphan account entry. Carries the fields the
// SaaS analyzer needs to render a row + the matchPattern symbolic tag so
// it knows whether the account was flagged by creationType, by UPN regex,
// or both.
type FirstPartyAccount struct {
	ID                 string     `json:"id"`
	UserPrincipalName  string     `json:"userPrincipalName"`
	DisplayName        string     `json:"displayName,omitempty"`
	CreationType       string     `json:"creationType,omitempty"` // empty when absent on the user
	CreatedDateTime    *time.Time `json:"createdDateTime,omitempty"`
	LastSignInDateTime *time.Time `json:"lastSignInDateTime,omitempty"`
	AccountEnabled     bool       `json:"accountEnabled"`
	UserType           string     `json:"userType,omitempty"`
	// MatchPattern is the symbolic name of the UPN regex that matched
	// (e.g. "bookings", "forms", "svc"). Empty when only creationType
	// triggered the inclusion.
	MatchPattern string `json:"matchPattern,omitempty"`
}
