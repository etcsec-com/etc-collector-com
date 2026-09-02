package types

import (
	"encoding/json"
	"time"
)

// === v3.1.38 §3 — Conditional Access policies (full nested detail) ===
//
// Mirrors the Microsoft Graph /identity/conditionalAccess/policies shape so
// the SaaS analyzer can compute adoption % per session control / grant control
// (Token Protection, Sign-in Frequency, Persistent Browser, Authentication
// Strength, ...) without losing fields.
//
// The existing flat ConditionalAccessPolicy type stays in place — it backs the
// in-collector detectors. ConditionalAccessPolicyDetail is the *additional*
// payload exposed in the audit JSON for downstream consumers.
//
// Complex/rare fields use json.RawMessage so the data round-trips intact even
// when the shape evolves on the Graph side (devices, authenticationFlows,
// includeGuestsOrExternalUsers, cloudAppSecurity).

// ConditionalAccessPolicyDetail is one CA policy with its nested conditions,
// grant controls and session controls preserved as Microsoft Graph returns
// them.
type ConditionalAccessPolicyDetail struct {
	ID               string                   `json:"id"`
	DisplayName      string                   `json:"displayName"`
	State            string                   `json:"state"` // enabled | disabled | enabledForReportingButNotEnforced
	CreatedDateTime  *time.Time               `json:"createdDateTime,omitempty"`
	ModifiedDateTime *time.Time               `json:"modifiedDateTime,omitempty"`
	TemplateID       string                   `json:"templateId,omitempty"`
	Conditions       *CADetailConditions      `json:"conditions,omitempty"`
	GrantControls    *CADetailGrantControls   `json:"grantControls,omitempty"`
	SessionControls  *CADetailSessionControls `json:"sessionControls,omitempty"`
}

// CADetailConditions mirrors the conditions block.
type CADetailConditions struct {
	Applications        *CADetailApplications `json:"applications,omitempty"`
	Users               *CADetailUsers        `json:"users,omitempty"`
	ClientAppTypes      []string              `json:"clientAppTypes,omitempty"`
	Platforms           *CADetailPlatforms    `json:"platforms,omitempty"`
	Locations           *CADetailLocations    `json:"locations,omitempty"`
	SignInRiskLevels    []string              `json:"signInRiskLevels,omitempty"`
	UserRiskLevels      []string              `json:"userRiskLevels,omitempty"`
	Devices             json.RawMessage       `json:"devices,omitempty"`             // pass-through (rarely populated)
	DeviceStates        json.RawMessage       `json:"deviceStates,omitempty"`        // legacy
	AuthenticationFlows json.RawMessage       `json:"authenticationFlows,omitempty"` // beta-only newer
}

// CADetailApplications mirrors conditions.applications.
type CADetailApplications struct {
	IncludeApplications                         []string `json:"includeApplications,omitempty"`
	ExcludeApplications                         []string `json:"excludeApplications,omitempty"`
	IncludeUserActions                          []string `json:"includeUserActions,omitempty"`
	IncludeAuthenticationContextClassReferences []string `json:"includeAuthenticationContextClassReferences,omitempty"`
}

// CADetailUsers mirrors conditions.users.
type CADetailUsers struct {
	IncludeUsers                 []string        `json:"includeUsers,omitempty"`
	ExcludeUsers                 []string        `json:"excludeUsers,omitempty"`
	IncludeGroups                []string        `json:"includeGroups,omitempty"`
	ExcludeGroups                []string        `json:"excludeGroups,omitempty"`
	IncludeRoles                 []string        `json:"includeRoles,omitempty"`
	ExcludeRoles                 []string        `json:"excludeRoles,omitempty"`
	IncludeGuestsOrExternalUsers json.RawMessage `json:"includeGuestsOrExternalUsers,omitempty"`
	ExcludeGuestsOrExternalUsers json.RawMessage `json:"excludeGuestsOrExternalUsers,omitempty"`
}

// CADetailPlatforms mirrors conditions.platforms.
type CADetailPlatforms struct {
	IncludePlatforms []string `json:"includePlatforms,omitempty"`
	ExcludePlatforms []string `json:"excludePlatforms,omitempty"`
}

// CADetailLocations mirrors conditions.locations.
type CADetailLocations struct {
	IncludeLocations []string `json:"includeLocations,omitempty"`
	ExcludeLocations []string `json:"excludeLocations,omitempty"`
}

// CADetailGrantControls mirrors the grantControls block.
type CADetailGrantControls struct {
	Operator                    string                          `json:"operator,omitempty"` // AND | OR
	BuiltInControls             []string                        `json:"builtInControls,omitempty"`
	CustomAuthenticationFactors []string                        `json:"customAuthenticationFactors,omitempty"`
	TermsOfUse                  []string                        `json:"termsOfUse,omitempty"`
	AuthenticationStrength      *CADetailAuthenticationStrength `json:"authenticationStrength,omitempty"`
}

// CADetailAuthenticationStrength mirrors grantControls.authenticationStrength.
type CADetailAuthenticationStrength struct {
	ID          string `json:"id,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	PolicyType  string `json:"policyType,omitempty"` // builtIn | custom
}

// CADetailSessionControls mirrors the sessionControls block.
type CADetailSessionControls struct {
	ApplicationEnforcedRestrictions *CADetailToggle                     `json:"applicationEnforcedRestrictions,omitempty"`
	CloudAppSecurity                json.RawMessage                     `json:"cloudAppSecurity,omitempty"`
	PersistentBrowser               *CADetailPersistentBrowser          `json:"persistentBrowser,omitempty"`
	SignInFrequency                 *CADetailSignInFrequency            `json:"signInFrequency,omitempty"`
	ContinuousAccessEvaluation      *CADetailContinuousAccessEvaluation `json:"continuousAccessEvaluation,omitempty"`
	SecureSignInSession             *CADetailToggle                     `json:"secureSignInSession,omitempty"`
	DisableResilienceDefaults       *bool                               `json:"disableResilienceDefaults,omitempty"`
	TokenProtection                 *CADetailTokenProtection            `json:"tokenProtection,omitempty"`
}

// CADetailToggle is the simple {isEnabled: bool} shape used by several controls.
type CADetailToggle struct {
	IsEnabled bool `json:"isEnabled"`
}

// CADetailContinuousAccessEvaluation mirrors sessionControls.continuousAccessEvaluation.
//
// Microsoft Graph returns this control with a `mode` enum (strictEnforcement |
// disabled), NOT an `isEnabled` boolean — unlike most other session controls.
// The previous v3.1.38 §3 modelling used CADetailToggle here, which silently
// dropped `mode` and yielded IsEnabled=false on every policy. This dedicated
// type captures `mode` and exposes IsEnabled as a derived backward-compat
// boolean (true iff mode == "strictEnforcement"). Both fields are written to
// the JSON payload so consumers can read either.
type CADetailContinuousAccessEvaluation struct {
	Mode      string `json:"mode,omitempty"` // strictEnforcement | disabled
	IsEnabled bool   `json:"isEnabled"`      // derived: mode == "strictEnforcement"
}

// UnmarshalJSON populates Mode from the wire payload and derives IsEnabled
// (Microsoft Graph never sends isEnabled for CAE — only mode). If a future
// payload version starts to carry isEnabled directly, that wire value wins.
func (c *CADetailContinuousAccessEvaluation) UnmarshalJSON(b []byte) error {
	var raw struct {
		Mode      string `json:"mode,omitempty"`
		IsEnabled *bool  `json:"isEnabled,omitempty"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	c.Mode = raw.Mode
	if raw.IsEnabled != nil {
		c.IsEnabled = *raw.IsEnabled
	} else {
		c.IsEnabled = raw.Mode == CAEModeStrictEnforcement
	}
	return nil
}

// CAE mode enum values per Microsoft Graph continuousAccessEvaluationMode.
const (
	CAEModeStrictEnforcement = "strictEnforcement"
	CAEModeDisabled          = "disabled"
)

// CADetailPersistentBrowser mirrors sessionControls.persistentBrowser.
type CADetailPersistentBrowser struct {
	IsEnabled bool   `json:"isEnabled"`
	Mode      string `json:"mode,omitempty"` // always | never
}

// CADetailSignInFrequency mirrors sessionControls.signInFrequency.
type CADetailSignInFrequency struct {
	IsEnabled          bool   `json:"isEnabled"`
	Type               string `json:"type,omitempty"` // hours | days
	Value              int    `json:"value,omitempty"`
	FrequencyInterval  string `json:"frequencyInterval,omitempty"`  // timeBased | everyTime
	AuthenticationType string `json:"authenticationType,omitempty"` // primaryAndSecondaryAuthentication | secondaryAuthentication
}

// CADetailTokenProtection mirrors sessionControls.tokenProtection.
type CADetailTokenProtection struct {
	IsEnabled bool `json:"isEnabled"`
}
