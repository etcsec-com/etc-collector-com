// Package types — Azure sign-in logs (v3.1.30 §1).
//
// This file carries the structured shape of a single Azure AD / Entra sign-in
// event as returned by Graph /beta/auditLogs/signIns, plus an aggregated
// summary used when the SaaS only wants counters instead of every event.
//
// The collector emits raw events by default (mode=raw) because the SOC use
// cases enabled by this collection — impossible travel, push fatigue, AITM
// signal, Service Principal sign-in spikes, device-code flow tracking,
// cross-tenant sign-ins — are all event-level. Aggregating discards the
// signal. Mode "aggregated" stays available for light reporting use cases.

package types

import "time"

// SignInLog mirrors the Graph /beta/auditLogs/signIns entry. Field
// selection matches r-azure-signin-logs-deep-v3_1_30-N_01: enough to power
// the 6 SOC patterns + Conditional Access policy hits + device posture.
//
// Beta-only fields (riskEventTypes_v2, incomingTokenType, resourceDisplayName)
// are tagged by their Graph beta name so unmarshalling against beta payloads
// works without a second decode pass.
type SignInLog struct {
	ID                               string                  `json:"id"`
	CreatedDateTime                  time.Time               `json:"createdDateTime"`
	UserID                           string                  `json:"userId,omitempty"`
	UserPrincipalName                string                  `json:"userPrincipalName,omitempty"`
	UserDisplayName                  string                  `json:"userDisplayName,omitempty"`
	UserType                         string                  `json:"userType,omitempty"` // Member | Guest
	AppID                            string                  `json:"appId,omitempty"`
	AppDisplayName                   string                  `json:"appDisplayName,omitempty"`
	ClientAppUsed                    string                  `json:"clientAppUsed,omitempty"`
	ConditionalAccessStatus          string                  `json:"conditionalAccessStatus,omitempty"` // success|failure|notApplied
	AppliedConditionalAccessPolicies []SignInAppliedCAPolicy `json:"appliedConditionalAccessPolicies,omitempty"`
	AuthenticationProtocol           string                  `json:"authenticationProtocol,omitempty"`
	AuthenticationDetails            []SignInAuthDetail      `json:"authenticationDetails,omitempty"`
	RiskState                        string                  `json:"riskState,omitempty"`
	RiskLevelAggregated              string                  `json:"riskLevelAggregated,omitempty"`
	RiskLevelDuringSignIn            string                  `json:"riskLevelDuringSignIn,omitempty"`
	RiskEventTypesV2                 []string                `json:"riskEventTypes_v2,omitempty"` // beta only
	TokenIssuerType                  string                  `json:"tokenIssuerType,omitempty"`
	CrossTenantAccessType            string                  `json:"crossTenantAccessType,omitempty"`
	SignInIdentifier                 string                  `json:"signInIdentifier,omitempty"`
	SignInIdentifierType             string                  `json:"signInIdentifierType,omitempty"`
	Location                         *SignInLocation         `json:"location,omitempty"`
	IPAddress                        string                  `json:"ipAddress,omitempty"`
	DeviceDetail                     *SignInDeviceDetail     `json:"deviceDetail,omitempty"`
	Status                           *SignInStatus           `json:"status,omitempty"`
	CorrelationID                    string                  `json:"correlationId,omitempty"`
	SessionLifetimePolicies          []SignInSessionPolicy   `json:"sessionLifetimePolicies,omitempty"`
	IncomingTokenType                string                  `json:"incomingTokenType,omitempty"` // beta only
	// Graph beta exposes this as a slice (a single event can carry multiple
	// types in theory). Possible values: interactiveUser | nonInteractiveUser
	// | servicePrincipal | managedIdentity. We expose it under the original
	// Graph name so the SaaS analyzer reads the same JSON Microsoft documents.
	SignInEventTypes []string `json:"signInEventTypes,omitempty"`
}

type SignInLocation struct {
	City            string `json:"city,omitempty"`
	State           string `json:"state,omitempty"`
	CountryOrRegion string `json:"countryOrRegion,omitempty"`
}

type SignInDeviceDetail struct {
	DeviceID        string `json:"deviceId,omitempty"`
	DisplayName     string `json:"displayName,omitempty"`
	OperatingSystem string `json:"operatingSystem,omitempty"`
	Browser         string `json:"browser,omitempty"`
	IsCompliant     *bool  `json:"isCompliant,omitempty"`
	IsManaged       *bool  `json:"isManaged,omitempty"`
}

type SignInStatus struct {
	ErrorCode         int    `json:"errorCode"`
	FailureReason     string `json:"failureReason,omitempty"`
	AdditionalDetails string `json:"additionalDetails,omitempty"`
}

type SignInAppliedCAPolicy struct {
	ID                      string   `json:"id,omitempty"`
	DisplayName             string   `json:"displayName,omitempty"`
	EnforcedGrantControls   []string `json:"enforcedGrantControls,omitempty"`
	EnforcedSessionControls []string `json:"enforcedSessionControls,omitempty"`
	Result                  string   `json:"result,omitempty"` // success | failure | notApplied | reportOnlySuccess | reportOnlyFailure
}

type SignInAuthDetail struct {
	AuthenticationStepDateTime     time.Time `json:"authenticationStepDateTime,omitempty"`
	AuthenticationMethod           string    `json:"authenticationMethod,omitempty"`
	AuthenticationMethodDetail     string    `json:"authenticationMethodDetail,omitempty"`
	Succeeded                      bool      `json:"succeeded"`
	AuthenticationStepResultDetail string    `json:"authenticationStepResultDetail,omitempty"`
}

type SignInSessionPolicy struct {
	ExpirationType        string `json:"expirationType,omitempty"`
	Detail                string `json:"detail,omitempty"`
	ExpirationRequirement string `json:"expirationRequirement,omitempty"`
}

// SignInLogsAggregated rolls up a slice of SignInLog into the smaller summary
// shape requested by Mode B in the spec. Counters + per-bucket breakdowns +
// the full risky subset (preserved as raw events for downstream correlation)
// + top-50 users + per-Service-Principal roll-ups with the last 100 events
// per SP for ConsentFix-style detection.
type SignInLogsAggregated struct {
	Total                int                `json:"total"`
	SuccessCount         int                `json:"successCount"`
	FailureCount         int                `json:"failureCount"`
	MFACount             int                `json:"mfaCount"`
	LegacyAuthCount      int                `json:"legacyAuthCount"`
	DeviceCodeCount      int                `json:"deviceCodeCount"`
	CrossTenantCount     int                `json:"crossTenantCount"`
	GuestCount           int                `json:"guestCount"`
	ByClientApp          []SignInBucket     `json:"byClientApp,omitempty"`
	ByAuthProtocol       []SignInBucket     `json:"byAuthProtocol,omitempty"`
	ByCountry            []SignInBucket     `json:"byCountry,omitempty"`
	BySignInType         []SignInBucket     `json:"bySignInType,omitempty"`
	RiskySignIns         []SignInLog        `json:"riskySignIns,omitempty"`         // raw subset, riskState != none
	TopUsersByVolume     []SignInUserVolume `json:"topUsersByVolume,omitempty"`     // top 50
	TopServicePrincipals []SignInSPVolume   `json:"topServicePrincipals,omitempty"` // SP sign-ins agrégés + last 100 events each
}

// SignInBucket — generic key/count breakdown.
type SignInBucket struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// SignInUserVolume — per-user sign-in count for top-N user lists.
type SignInUserVolume struct {
	UserPrincipalName string `json:"userPrincipalName"`
	UserDisplayName   string `json:"userDisplayName,omitempty"`
	Count             int    `json:"count"`
}

// SignInSPVolume — per-Service-Principal roll-up. LastEvents preserves the
// most recent 100 raw events per SP so the SaaS can correlate consent
// phishing patterns (e.g. spike on a SP nobody created legitimately).
type SignInSPVolume struct {
	AppID          string      `json:"appId"`
	AppDisplayName string      `json:"appDisplayName,omitempty"`
	Count          int         `json:"count"`
	LastEvents     []SignInLog `json:"lastEvents,omitempty"`
}
