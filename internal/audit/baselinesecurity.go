// Package audit — Microsoft Baseline Security Mode adoption (v3.1.37 §1).
//
// Pure post-collection aggregator. Walks the data already on DetectorData
// (Security Defaults, Conditional Access policies, Auth Methods Policy,
// Authorization Policy, Admin Consent Request Policy) and produces the
// audit.baselineSecurity payload that powers the SaaS Executive Tab
// "Baseline Adoption" widget + KPI #20.
//
// No Graph roundtrip in this file — the upstream collector layer
// (engine.collectAzureData) already populated everything we read here.
//
// The 20 baseline policy IDs and their definitions are hardcoded in
// baselinePolicyDefs so an audit JSON can be reproduced from the version
// that emitted it (auditor traceability requirement). When Microsoft
// updates the recommended baseline, bump baselinePolicyDefs in a release
// commit; the SaaS analyzer reads new/disappeared IDs through the payload.

package audit

import (
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// baselineLicense describes the minimum Entra license tier a policy needs to
// be configurable. Used to mark policies as "not_available" on tenants that
// don't have the SKU instead of penalising them with "disabled".
type baselineLicense string

const (
	licenseNone baselineLicense = "none" // any Entra tenant
	licenseP1   baselineLicense = "p1"   // Entra ID P1 features
	licenseP2   baselineLicense = "p2"   // Entra ID P2 (Identity Protection risk policies)
)

// baselinePolicyEval is the per-check verdict produced by a check func.
// Status mirrors types.BaselinePolicyResult.Status. Helper checkXxx funcs
// return one of these; BuildBaselineSecuritySummary maps it onto the
// public BaselinePolicyResult shape.
type baselinePolicyEval struct {
	status   string // enabled | disabled | partial | unknown | not_available
	evidence *types.BaselinePolicyEvidence
	reason   string
}

// baselinePolicyDef is the static definition of one of the 20 baseline
// policies. Check is the lambda that produces a verdict from already-
// collected data.
type baselinePolicyDef struct {
	ID              string
	Name            string
	Description     string
	Impact          string // high | medium | low
	RequiresLicense baselineLicense
	Remediation     string
	Check           func(d *DetectorData) baselinePolicyEval
}

// baselinePolicyDefs is the canonical list shipped with this binary. Order
// is stable and meaningful (the SaaS UI renders policies in this order in
// the "Baseline Adoption" widget, grouped by impact).
//
// Sources:
//   - Microsoft Learn "Microsoft Entra recommended security baselines" (Nov 2025)
//   - CIS Microsoft 365 Foundations Benchmark v3
//   - ANSSI Recommandations Entra
//
// When Microsoft updates the list, bump this slice in a release commit.
var baselinePolicyDefs = []baselinePolicyDef{
	{
		ID:              "BL_SECURITY_DEFAULTS_OR_CA_EQUIVALENT",
		Name:            "Security Defaults enabled or replaced by equivalent CA policies",
		Description:     "Either Microsoft Security Defaults are on, or a tenant-wide MFA + legacy-auth-block CA policy stack replaces them.",
		Impact:          "high",
		RequiresLicense: licenseNone,
		Remediation:     "Enable Security Defaults in Entra → Identity → Protection, OR roll out an MFA-required + legacy-auth-blocked CA policy targeting all users.",
		Check:           checkSecurityDefaultsOrEquivalent,
	},
	{
		ID:              "BL_MFA_ALL_USERS",
		Name:            "MFA required for all users",
		Description:     "A Conditional Access policy requires MFA for the All Users target.",
		Impact:          "high",
		RequiresLicense: licenseP1,
		Remediation:     "Create a CA policy: include All Users, all cloud apps, grant control = require MFA, state = enabled.",
		Check:           checkMFAAllUsers,
	},
	{
		ID:              "BL_MFA_ADMINS",
		Name:            "MFA required for all administrators",
		Description:     "A Conditional Access policy requires MFA for every Entra built-in admin role.",
		Impact:          "high",
		RequiresLicense: licenseNone,
		Remediation:     "Create a CA policy: include all admin directory roles, grant control = require MFA, state = enabled.",
		Check:           checkMFAAdmins,
	},
	{
		ID:              "BL_BLOCK_LEGACY_AUTH",
		Name:            "Legacy authentication protocols blocked",
		Description:     "POP, IMAP, SMTP, MAPI and other legacy auth protocols are blocked via CA.",
		Impact:          "high",
		RequiresLicense: licenseP1,
		Remediation:     "Create a CA policy: include All Users, clientAppTypes = exchangeActiveSync + other (legacy), grant control = block.",
		Check:           checkBlockLegacyAuth,
	},
	{
		ID:              "BL_BLOCK_HIGH_RISK_SIGNIN",
		Name:            "High-risk sign-ins blocked",
		Description:     "A CA policy blocks sign-ins flagged High by Identity Protection.",
		Impact:          "high",
		RequiresLicense: licenseP2,
		Remediation:     "Create a CA policy: signInRiskLevels = ['high'], grant control = block.",
		Check:           checkBlockHighRiskSignIn,
	},
	{
		ID:              "BL_BLOCK_HIGH_RISK_USER",
		Name:            "High-risk users blocked or forced to remediate",
		Description:     "A CA policy blocks or forces password reset for users flagged High by Identity Protection.",
		Impact:          "high",
		RequiresLicense: licenseP2,
		Remediation:     "Create a CA policy: userRiskLevels = ['high'], grant control = block OR password change.",
		Check:           checkBlockHighRiskUser,
	},
	{
		ID:              "BL_REQUIRE_DEVICE_COMPLIANCE",
		Name:            "Compliant or hybrid-joined device required",
		Description:     "A CA policy requires a compliant device or hybrid-joined device to access cloud apps.",
		Impact:          "medium",
		RequiresLicense: licenseP1,
		Remediation:     "Create a CA policy: grant controls include compliantDevice OR domainJoinedDevice.",
		Check:           checkRequireDeviceCompliance,
	},
	{
		ID:              "BL_REQUIRE_HYBRID_JOIN_ADMINS",
		Name:            "Admin sign-ins require hybrid-joined or compliant device",
		Description:     "A CA policy targeting privileged roles requires a hybrid-joined or compliant device.",
		Impact:          "medium",
		RequiresLicense: licenseP1,
		Remediation:     "Create a CA policy: include privileged roles, grant control = compliantDevice OR domainJoinedDevice.",
		Check:           checkRequireHybridJoinAdmins,
	},
	{
		ID:              "BL_BLOCK_DEVICE_CODE_FLOW",
		Name:            "Device code flow blocked",
		Description:     "A CA policy blocks the device code authentication flow (commonly abused for phishing).",
		Impact:          "medium",
		RequiresLicense: licenseP1,
		Remediation:     "Create a CA policy: condition authenticationFlows = deviceCodeFlow, grant control = block.",
		Check:           checkBlockDeviceCodeFlow,
	},
	{
		ID:              "BL_REQUIRE_MFA_REGISTRATION",
		Name:            "MFA registration enforced via Identity Protection",
		Description:     "A CA policy targeting userRiskLevels enforces MFA registration on flagged users.",
		Impact:          "medium",
		RequiresLicense: licenseP2,
		Remediation:     "Enable Identity Protection MFA registration policy OR a CA policy with userRiskLevels including any non-empty level + grant control require MFA.",
		Check:           checkRequireMFARegistration,
	},
	{
		ID:              "BL_FIDO2_ENABLED",
		Name:            "FIDO2 security keys enabled",
		Description:     "FIDO2 / passkey authentication method is enabled in the Authentication Methods policy.",
		Impact:          "medium",
		RequiresLicense: licenseNone,
		Remediation:     "Entra → Identity → Authentication methods → FIDO2 → state = Enabled, target = All Users.",
		Check:           checkFIDO2Enabled,
	},
	{
		ID:              "BL_PASSWORDLESS_PHONE_SIGNIN",
		Name:            "Microsoft Authenticator passwordless enabled",
		Description:     "The Microsoft Authenticator method is enabled (covers passwordless phone sign-in).",
		Impact:          "medium",
		RequiresLicense: licenseNone,
		Remediation:     "Entra → Identity → Authentication methods → Microsoft Authenticator → state = Enabled.",
		Check:           checkPasswordlessPhoneSignIn,
	},
	{
		ID:              "BL_TAP_ENABLED",
		Name:            "Temporary Access Pass enabled",
		Description:     "TAP method is enabled, allowing onboarding without password.",
		Impact:          "low",
		RequiresLicense: licenseNone,
		Remediation:     "Entra → Identity → Authentication methods → Temporary Access Pass → state = Enabled.",
		Check:           checkTAPEnabled,
	},
	{
		ID:              "BL_SMS_DISABLED",
		Name:            "SMS authentication disabled (legacy)",
		Description:     "SMS as a sign-in / MFA method is disabled — Microsoft and CISA both recommend phasing it out.",
		Impact:          "medium",
		RequiresLicense: licenseNone,
		Remediation:     "Entra → Identity → Authentication methods → SMS → state = Disabled.",
		Check:           checkSMSDisabled,
	},
	{
		ID:              "BL_BLOCK_USER_CONSENT_RISKY_APPS",
		Name:            "User consent restricted for risky apps",
		Description:     "Authorization policy blocks user consent to risky third-party apps.",
		Impact:          "high",
		RequiresLicense: licenseNone,
		Remediation:     "Entra → Identity → Enterprise applications → Consent and permissions → Allow user consent for apps from verified publishers, for selected permissions.",
		Check:           checkBlockUserConsentRiskyApps,
	},
	{
		ID:              "BL_DISABLE_USER_APP_CREATION",
		Name:            "Default users cannot register applications",
		Description:     "Authorization policy disables app registration for the default user role.",
		Impact:          "medium",
		RequiresLicense: licenseNone,
		Remediation:     "Entra → Identity → User settings → Users can register applications = No.",
		Check:           checkDisableUserAppCreation,
	},
	{
		ID:              "BL_DISABLE_USER_TENANT_CREATION",
		Name:            "Default users cannot create new tenants",
		Description:     "Authorization policy disables tenant creation for the default user role.",
		Impact:          "medium",
		RequiresLicense: licenseNone,
		Remediation:     "Entra → Identity → User settings → Users can create tenants = No.",
		Check:           checkDisableUserTenantCreation,
	},
	{
		ID:              "BL_RESTRICT_AAD_ADMIN_PORTAL",
		Name:            "Non-admins blocked from Azure AD admin portal",
		Description:     "A CA policy blocks the Microsoft Azure Management app for non-admins.",
		Impact:          "medium",
		RequiresLicense: licenseP1,
		Remediation:     "Create a CA policy: include All Users + exclude admin roles, target Microsoft Azure Management app, grant control = block.",
		Check:           checkRestrictAdminPortal,
	},
	{
		ID:              "BL_TOKEN_PROTECTION_ENABLED",
		Name:            "Token Protection (sign-in session binding) enabled",
		Description:     "A CA policy enables Token Protection session control on at least one critical scope.",
		Impact:          "medium",
		RequiresLicense: licenseP2,
		Remediation:     "Create a CA policy: session controls → enable Token Protection. Currently in preview on Windows 10/11 + Microsoft 365 apps.",
		Check:           checkTokenProtectionEnabled,
	},
	{
		ID:              "BL_GUEST_INVITE_RESTRICTED",
		Name:            "Guest invitations restricted to admins or specific role",
		Description:     "Authorization policy disallows everyone-can-invite. Limited to admin / inviter role / no guests.",
		Impact:          "low",
		RequiresLicense: licenseNone,
		Remediation:     "Entra → External Identities → External collaboration settings → Guest invite settings → adminsAndGuestInviters or stricter.",
		Check:           checkGuestInviteRestricted,
	},
}

// BuildBaselineSecuritySummary walks the baselinePolicyDefs and aggregates
// the verdicts into the SaaS-facing summary. Pure: deterministic for a
// given DetectorData snapshot. version is the collector binary version
// (passed by the engine so the helper stays decoupled from cmd/ symbols).
func BuildBaselineSecuritySummary(data *DetectorData, version string) *types.BaselineSecuritySummary {
	if data == nil {
		return nil
	}
	summary := &types.BaselineSecuritySummary{
		TotalPolicies:    len(baselinePolicyDefs),
		CollectorVersion: version,
		Policies:         make([]types.BaselinePolicyResult, 0, len(baselinePolicyDefs)),
	}

	for _, def := range baselinePolicyDefs {
		eval := def.Check(data)
		// License gate: if the tenant doesn't have the required SKU, override
		// the verdict to not_available so we don't penalise for what they can't
		// configure. We let the check func run anyway (cheap + tests-friendly).
		if eval.status != "not_available" && tenantBelowLicense(data.AzureLicenseTier, def.RequiresLicense) {
			eval = baselinePolicyEval{
				status: "not_available",
				reason: fmt.Sprintf("requires Entra %s license", def.RequiresLicense),
			}
		}
		result := types.BaselinePolicyResult{
			ID:          def.ID,
			Name:        def.Name,
			Description: def.Description,
			Impact:      def.Impact,
			Status:      eval.status,
			Evidence:    eval.evidence,
			Reason:      eval.reason,
		}
		// Remediation only when actionable — disabled or partial. enabled / unknown
		// / not_available don't need it (and would clutter the SaaS UI).
		if eval.status == "disabled" || eval.status == "partial" {
			result.Remediation = def.Remediation
		}
		summary.Policies = append(summary.Policies, result)

		switch eval.status {
		case "enabled":
			summary.EnabledCount++
		case "disabled":
			summary.DisabledCount++
		case "partial":
			summary.PartialCount++
		case "unknown":
			summary.UnknownCount++
		case "not_available":
			summary.NotAvailableCount++
		}
	}

	// Score formula: (enabled + 0.5*partial) / availablePolicies * 100.
	// availablePolicies excludes both not_available (license-gated) and
	// unknown (data-missing) so the % reflects what the tenant could actually
	// have done with what we could observe.
	available := summary.TotalPolicies - summary.NotAvailableCount - summary.UnknownCount
	if available > 0 {
		raw := (float64(summary.EnabledCount) + 0.5*float64(summary.PartialCount)) / float64(available) * 100
		summary.Score = int(raw + 0.5) // round half up
	} // else Score stays 0

	return summary
}

// tenantBelowLicense returns true when tier (raw "free"|"p1"|"p2") is
// strictly below requires. Empty tier (license detection failed) doesn't
// route to not_available — the check returns its own verdict (likely
// "unknown" if data is missing).
func tenantBelowLicense(tier string, requires baselineLicense) bool {
	if requires == licenseNone {
		return false
	}
	tier = strings.ToLower(strings.TrimSpace(tier))
	if tier == "" {
		return false // unknown tier — let the check decide
	}
	rank := func(s string) int {
		switch s {
		case "free":
			return 0
		case "p1":
			return 1
		case "p2":
			return 2
		}
		return -1 // unknown rank
	}
	tierRank := rank(tier)
	reqRank := rank(string(requires))
	if tierRank < 0 || reqRank < 0 {
		return false
	}
	return tierRank < reqRank
}

// === check helpers ============================================================

// caHasGrantControl returns true if the CA policy is enabled and its
// grant controls contain any of the wanted strings (case-insensitive).
func caHasGrantControl(p *types.ConditionalAccessPolicy, wanted ...string) bool {
	if p == nil || !strings.EqualFold(p.State, "enabled") {
		return false
	}
	for _, ctrl := range p.GrantControls {
		for _, w := range wanted {
			if strings.EqualFold(ctrl, w) {
				return true
			}
		}
	}
	return false
}

// caTargetsAllUsers returns true when the CA policy explicitly targets
// the special "All" users token — Graph emits "All" or "all" depending on
// flow; we accept both.
func caTargetsAllUsers(p *types.ConditionalAccessPolicy) bool {
	if p == nil {
		return false
	}
	for _, u := range p.IncludeUsers {
		if strings.EqualFold(u, "All") {
			return true
		}
	}
	return false
}

// caTargetsAdminRoles returns true when the CA policy includes at least
// one Entra built-in admin role (any non-empty IncludeRoles is a strong
// signal — admins curate that field deliberately).
func caTargetsAdminRoles(p *types.ConditionalAccessPolicy) bool {
	return p != nil && len(p.IncludeRoles) > 0
}

// caTargetsAllOrAnyApp returns true when the CA policy targets All apps or
// at least one cloud app (we don't try to enumerate apps — coverage of
// "any cloud app" is good enough for a baseline check).
func caTargetsAllOrAnyApp(p *types.ConditionalAccessPolicy) bool {
	if p == nil {
		return false
	}
	for _, a := range p.IncludeApps {
		if strings.EqualFold(a, "All") || a != "" {
			return true
		}
	}
	return false
}

// firstEvidence builds an evidence object pointing at a CA policy.
func caEvidence(p *types.ConditionalAccessPolicy, details string) *types.BaselinePolicyEvidence {
	if p == nil {
		return nil
	}
	return &types.BaselinePolicyEvidence{
		PolicyType: "conditionalAccess",
		PolicyID:   p.ID,
		PolicyName: p.DisplayName,
		Details:    details,
	}
}

// findMatchingCA scans the slice and returns the first enabled policy where
// match returns true. Caller picks the predicate.
func findMatchingCA(policies []types.ConditionalAccessPolicy, match func(*types.ConditionalAccessPolicy) bool) *types.ConditionalAccessPolicy {
	for i := range policies {
		p := &policies[i]
		if !strings.EqualFold(p.State, "enabled") {
			continue
		}
		if match(p) {
			return p
		}
	}
	return nil
}

// === 20 check funcs ==========================================================

func checkSecurityDefaultsOrEquivalent(d *DetectorData) baselinePolicyEval {
	if d.AzureTenantConfig != nil && d.AzureTenantConfig.SecurityDefaults != nil && d.AzureTenantConfig.SecurityDefaults.IsEnabled {
		return baselinePolicyEval{
			status: "enabled",
			evidence: &types.BaselinePolicyEvidence{
				PolicyType: "securityDefaults",
				PolicyName: "Security Defaults",
				Details:    "Microsoft Security Defaults enforced.",
			},
		}
	}
	// Fallback: equivalent CA stack (MFA all users + block legacy auth).
	mfa := checkMFAAllUsers(d)
	legacy := checkBlockLegacyAuth(d)
	if mfa.status == "enabled" && legacy.status == "enabled" {
		return baselinePolicyEval{
			status: "enabled",
			evidence: &types.BaselinePolicyEvidence{
				PolicyType: "conditionalAccess",
				Details:    "Equivalent CA stack: MFA-all-users + Block-legacy-auth both enabled.",
			},
		}
	}
	return baselinePolicyEval{status: "disabled", reason: "Security Defaults off and no equivalent CA stack found."}
}

func checkMFAAllUsers(d *DetectorData) baselinePolicyEval {
	p := findMatchingCA(d.AzureConditionalAccessPolicies, func(p *types.ConditionalAccessPolicy) bool {
		return caTargetsAllUsers(p) && caTargetsAllOrAnyApp(p) && caHasGrantControl(p, "mfa", "passwordlessAuthentication")
	})
	if p != nil {
		return baselinePolicyEval{status: "enabled", evidence: caEvidence(p, "MFA grant control on All Users.")}
	}
	return baselinePolicyEval{status: "disabled", reason: "No enabled CA policy with MFA + All Users + cloud apps."}
}

func checkMFAAdmins(d *DetectorData) baselinePolicyEval {
	p := findMatchingCA(d.AzureConditionalAccessPolicies, func(p *types.ConditionalAccessPolicy) bool {
		return caTargetsAdminRoles(p) && caHasGrantControl(p, "mfa", "passwordlessAuthentication", "authenticationStrength")
	})
	if p != nil {
		return baselinePolicyEval{status: "enabled", evidence: caEvidence(p, fmt.Sprintf("MFA grant control on %d admin role(s).", len(p.IncludeRoles)))}
	}
	// Fallback: Security Defaults globally protect built-in admin roles
	if d.AzureTenantConfig != nil && d.AzureTenantConfig.SecurityDefaults != nil && d.AzureTenantConfig.SecurityDefaults.IsEnabled {
		return baselinePolicyEval{
			status: "enabled",
			evidence: &types.BaselinePolicyEvidence{
				PolicyType: "securityDefaults",
				Details:    "Security Defaults enforce MFA on all admin roles.",
			},
		}
	}
	return baselinePolicyEval{status: "disabled", reason: "No enabled CA policy with MFA + admin role targeting and Security Defaults are off."}
}

func checkBlockLegacyAuth(d *DetectorData) baselinePolicyEval {
	p := findMatchingCA(d.AzureConditionalAccessPolicies, func(p *types.ConditionalAccessPolicy) bool {
		hasLegacy := false
		for _, t := range p.ClientAppTypes {
			if strings.EqualFold(t, "exchangeActiveSync") || strings.EqualFold(t, "other") {
				hasLegacy = true
				break
			}
		}
		return hasLegacy && caHasGrantControl(p, "block")
	})
	if p != nil {
		return baselinePolicyEval{status: "enabled", evidence: caEvidence(p, "Legacy auth client apps blocked.")}
	}
	return baselinePolicyEval{status: "disabled", reason: "No enabled CA policy blocking exchangeActiveSync / other (legacy)."}
}

func checkBlockHighRiskSignIn(d *DetectorData) baselinePolicyEval {
	p := findMatchingCA(d.AzureConditionalAccessPolicies, func(p *types.ConditionalAccessPolicy) bool {
		hasHigh := false
		for _, l := range p.SignInRiskLevels {
			if strings.EqualFold(l, "high") {
				hasHigh = true
				break
			}
		}
		return hasHigh && caHasGrantControl(p, "block")
	})
	if p != nil {
		return baselinePolicyEval{status: "enabled", evidence: caEvidence(p, "Sign-in risk High → block.")}
	}
	return baselinePolicyEval{status: "disabled", reason: "No enabled CA policy with signInRiskLevels=['high'] + block."}
}

func checkBlockHighRiskUser(d *DetectorData) baselinePolicyEval {
	p := findMatchingCA(d.AzureConditionalAccessPolicies, func(p *types.ConditionalAccessPolicy) bool {
		hasHigh := false
		for _, l := range p.UserRiskLevels {
			if strings.EqualFold(l, "high") {
				hasHigh = true
				break
			}
		}
		return hasHigh && caHasGrantControl(p, "block", "passwordChange")
	})
	if p != nil {
		return baselinePolicyEval{status: "enabled", evidence: caEvidence(p, "User risk High → block / passwordChange.")}
	}
	return baselinePolicyEval{status: "disabled", reason: "No enabled CA policy with userRiskLevels=['high'] + block/passwordChange."}
}

func checkRequireDeviceCompliance(d *DetectorData) baselinePolicyEval {
	p := findMatchingCA(d.AzureConditionalAccessPolicies, func(p *types.ConditionalAccessPolicy) bool {
		return caHasGrantControl(p, "compliantDevice", "domainJoinedDevice")
	})
	if p != nil {
		return baselinePolicyEval{status: "enabled", evidence: caEvidence(p, "compliantDevice or domainJoinedDevice grant control.")}
	}
	return baselinePolicyEval{status: "disabled", reason: "No enabled CA policy requiring compliant or domain-joined device."}
}

func checkRequireHybridJoinAdmins(d *DetectorData) baselinePolicyEval {
	p := findMatchingCA(d.AzureConditionalAccessPolicies, func(p *types.ConditionalAccessPolicy) bool {
		return caTargetsAdminRoles(p) && caHasGrantControl(p, "compliantDevice", "domainJoinedDevice")
	})
	if p != nil {
		return baselinePolicyEval{status: "enabled", evidence: caEvidence(p, "Admin roles + compliantDevice/domainJoinedDevice grant control.")}
	}
	return baselinePolicyEval{status: "disabled", reason: "No enabled CA policy targeting admin roles with device compliance."}
}

func checkBlockDeviceCodeFlow(d *DetectorData) baselinePolicyEval {
	// We don't currently parse authenticationFlows on CA policies (Graph
	// adds it under conditions.authenticationFlows.transferMethods which
	// isn't on our struct). Conservative fallback: if SecurityDefaults are
	// on, device code is also implicitly limited; otherwise unknown.
	if d.AzureTenantConfig != nil && d.AzureTenantConfig.SecurityDefaults != nil && d.AzureTenantConfig.SecurityDefaults.IsEnabled {
		return baselinePolicyEval{
			status: "enabled",
			evidence: &types.BaselinePolicyEvidence{
				PolicyType: "securityDefaults",
				Details:    "Security Defaults restrict legacy auth flows (device code included).",
			},
		}
	}
	return baselinePolicyEval{
		status: "unknown",
		reason: "authenticationFlows condition not parsed on CA policies in this collector version; verify manually in Entra → Conditional Access.",
	}
}

func checkRequireMFARegistration(d *DetectorData) baselinePolicyEval {
	p := findMatchingCA(d.AzureConditionalAccessPolicies, func(p *types.ConditionalAccessPolicy) bool {
		return len(p.UserRiskLevels) > 0 && caHasGrantControl(p, "mfa", "passwordlessAuthentication")
	})
	if p != nil {
		return baselinePolicyEval{status: "enabled", evidence: caEvidence(p, "userRiskLevels-targeted MFA registration policy.")}
	}
	return baselinePolicyEval{status: "disabled", reason: "No enabled CA policy with userRiskLevels + MFA grant."}
}

// authMethodIsEnabled returns true if the per-method state is "enabled". Returns
// false for "disabled" / empty / nil. Reused by the FIDO2 / Authenticator / TAP / SMS checks.
func authMethodIsEnabled(state string) bool {
	return strings.EqualFold(state, "enabled")
}

// authMethodCoversAllUsers returns true when the method's includeTargets[]
// either is empty (Graph default = all users) or contains the special
// "all_users" identifier. Otherwise it's a partial coverage (specific group).
func authMethodCoversAllUsers(cfg types.AuthMethodConfig) bool {
	if len(cfg.IncludeTargets) == 0 {
		return true
	}
	for _, t := range cfg.IncludeTargets {
		if strings.EqualFold(t.ID, "all_users") {
			return true
		}
	}
	return false
}

func checkFIDO2Enabled(d *DetectorData) baselinePolicyEval {
	if d.AzureAuthMethodsDetail == nil || d.AzureAuthMethodsDetail.Policy == nil {
		return baselinePolicyEval{status: "unknown", reason: "AuthMethodsDetail.Policy not collected."}
	}
	cfg := d.AzureAuthMethodsDetail.Policy.FIDO2
	if !authMethodIsEnabled(cfg.State) {
		return baselinePolicyEval{status: "disabled", reason: "FIDO2 state != enabled."}
	}
	ev := &types.BaselinePolicyEvidence{
		PolicyType: "authenticationMethodsPolicy",
		PolicyName: "fido2",
	}
	if authMethodCoversAllUsers(cfg) {
		ev.Details = "FIDO2 enabled for all users."
		return baselinePolicyEval{status: "enabled", evidence: ev}
	}
	ev.Details = fmt.Sprintf("FIDO2 enabled but scoped to %d include target(s).", len(cfg.IncludeTargets))
	return baselinePolicyEval{status: "partial", evidence: ev, reason: "Scoped to a subset of users; expand to All Users."}
}

func checkPasswordlessPhoneSignIn(d *DetectorData) baselinePolicyEval {
	if d.AzureAuthMethodsDetail == nil || d.AzureAuthMethodsDetail.Policy == nil {
		return baselinePolicyEval{status: "unknown", reason: "AuthMethodsDetail.Policy not collected."}
	}
	cfg := d.AzureAuthMethodsDetail.Policy.MicrosoftAuthenticator
	if !authMethodIsEnabled(cfg.State) {
		return baselinePolicyEval{status: "disabled", reason: "Microsoft Authenticator state != enabled."}
	}
	ev := &types.BaselinePolicyEvidence{
		PolicyType: "authenticationMethodsPolicy",
		PolicyName: "microsoftAuthenticator",
	}
	if authMethodCoversAllUsers(cfg) {
		ev.Details = "Microsoft Authenticator enabled for all users."
		return baselinePolicyEval{status: "enabled", evidence: ev}
	}
	ev.Details = fmt.Sprintf("Enabled but scoped to %d include target(s).", len(cfg.IncludeTargets))
	return baselinePolicyEval{status: "partial", evidence: ev, reason: "Scoped to a subset of users; expand to All Users."}
}

func checkTAPEnabled(d *DetectorData) baselinePolicyEval {
	if d.AzureAuthMethodsDetail == nil || d.AzureAuthMethodsDetail.Policy == nil {
		return baselinePolicyEval{status: "unknown", reason: "AuthMethodsDetail.Policy not collected."}
	}
	cfg := d.AzureAuthMethodsDetail.Policy.TemporaryAccessPass
	if authMethodIsEnabled(cfg.State) {
		return baselinePolicyEval{
			status: "enabled",
			evidence: &types.BaselinePolicyEvidence{
				PolicyType: "authenticationMethodsPolicy",
				PolicyName: "temporaryAccessPass",
				Details:    "TAP method enabled.",
			},
		}
	}
	return baselinePolicyEval{status: "disabled", reason: "Temporary Access Pass state != enabled."}
}

func checkSMSDisabled(d *DetectorData) baselinePolicyEval {
	if d.AzureAuthMethodsDetail == nil || d.AzureAuthMethodsDetail.Policy == nil {
		return baselinePolicyEval{status: "unknown", reason: "AuthMethodsDetail.Policy not collected."}
	}
	cfg := d.AzureAuthMethodsDetail.Policy.SMS
	if !authMethodIsEnabled(cfg.State) {
		return baselinePolicyEval{
			status: "enabled",
			evidence: &types.BaselinePolicyEvidence{
				PolicyType: "authenticationMethodsPolicy",
				PolicyName: "sms",
				Details:    "SMS method disabled (legacy phase-out aligned with Microsoft + CISA guidance).",
			},
		}
	}
	return baselinePolicyEval{
		status: "disabled",
		reason: "SMS method is enabled — phase out per Microsoft + CISA guidance.",
	}
}

func checkBlockUserConsentRiskyApps(d *DetectorData) baselinePolicyEval {
	if d.AzureAuthorizationPolicy == nil {
		return baselinePolicyEval{status: "unknown", reason: "authorizationPolicy not collected (likely missing Policy.Read.All)."}
	}
	if d.AzureAuthorizationPolicy.AllowUserConsentForRiskyApps == nil {
		return baselinePolicyEval{status: "unknown", reason: "allowUserConsentForRiskyApps field absent from response."}
	}
	if !*d.AzureAuthorizationPolicy.AllowUserConsentForRiskyApps {
		return baselinePolicyEval{
			status: "enabled",
			evidence: &types.BaselinePolicyEvidence{
				PolicyType: "authorizationPolicy",
				Details:    "allowUserConsentForRiskyApps = false.",
			},
		}
	}
	return baselinePolicyEval{status: "disabled", reason: "allowUserConsentForRiskyApps = true (default — needs flip)."}
}

func checkDisableUserAppCreation(d *DetectorData) baselinePolicyEval {
	if d.AzureAuthorizationPolicy == nil || d.AzureAuthorizationPolicy.DefaultUserRolePermissions == nil {
		return baselinePolicyEval{status: "unknown", reason: "authorizationPolicy.defaultUserRolePermissions not collected."}
	}
	v := d.AzureAuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateApps
	if v == nil {
		return baselinePolicyEval{status: "unknown", reason: "allowedToCreateApps field absent."}
	}
	if !*v {
		return baselinePolicyEval{
			status: "enabled",
			evidence: &types.BaselinePolicyEvidence{
				PolicyType: "authorizationPolicy",
				Details:    "defaultUserRolePermissions.allowedToCreateApps = false.",
			},
		}
	}
	return baselinePolicyEval{status: "disabled", reason: "Default users can register applications."}
}

func checkDisableUserTenantCreation(d *DetectorData) baselinePolicyEval {
	if d.AzureAuthorizationPolicy == nil || d.AzureAuthorizationPolicy.DefaultUserRolePermissions == nil {
		return baselinePolicyEval{status: "unknown", reason: "authorizationPolicy.defaultUserRolePermissions not collected."}
	}
	v := d.AzureAuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateTenants
	if v == nil {
		return baselinePolicyEval{status: "unknown", reason: "allowedToCreateTenants field absent."}
	}
	if !*v {
		return baselinePolicyEval{
			status: "enabled",
			evidence: &types.BaselinePolicyEvidence{
				PolicyType: "authorizationPolicy",
				Details:    "defaultUserRolePermissions.allowedToCreateTenants = false.",
			},
		}
	}
	return baselinePolicyEval{status: "disabled", reason: "Default users can create new tenants."}
}

func checkRestrictAdminPortal(d *DetectorData) baselinePolicyEval {
	// Microsoft Azure Management app id = 797f4846-ba00-4fd7-ba43-dac1f8f63013
	const azureMgmtAppID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
	p := findMatchingCA(d.AzureConditionalAccessPolicies, func(p *types.ConditionalAccessPolicy) bool {
		hasMgmt := false
		for _, a := range p.IncludeApps {
			if a == azureMgmtAppID {
				hasMgmt = true
				break
			}
		}
		return hasMgmt && caHasGrantControl(p, "block")
	})
	if p != nil {
		return baselinePolicyEval{status: "enabled", evidence: caEvidence(p, "Microsoft Azure Management app gated.")}
	}
	return baselinePolicyEval{status: "disabled", reason: "No enabled CA policy gating the Microsoft Azure Management app."}
}

func checkTokenProtectionEnabled(d *DetectorData) baselinePolicyEval {
	// v3.1.38 §3 — read from the full nested CA detail slice. The flat
	// ConditionalAccessPolicy.TokenProtectionRequired field is never
	// populated by the SDK converter (the nested sessionControls.tokenProtection
	// shape isn't surfaced as a top-level boolean), so the previous check
	// always returned "disabled". The detail slice is fetched via raw HTTP
	// against /identity/conditionalAccess/policies and preserves
	// sessionControls.tokenProtection.isEnabled verbatim.
	if d.AzureConditionalAccessPolicyDetails == nil {
		return baselinePolicyEval{status: "unknown", reason: "Conditional Access policy detail not collected (Policy.Read.All scope likely missing)."}
	}
	for i := range d.AzureConditionalAccessPolicyDetails {
		p := &d.AzureConditionalAccessPolicyDetails[i]
		if !strings.EqualFold(p.State, "enabled") {
			continue
		}
		if p.SessionControls != nil && p.SessionControls.TokenProtection != nil && p.SessionControls.TokenProtection.IsEnabled {
			return baselinePolicyEval{
				status: "enabled",
				evidence: &types.BaselinePolicyEvidence{
					PolicyType: "conditionalAccess",
					PolicyID:   p.ID,
					PolicyName: p.DisplayName,
					Details:    "sessionControls.tokenProtection.isEnabled = true.",
				},
			}
		}
	}
	return baselinePolicyEval{status: "disabled", reason: "No enabled CA policy with sessionControls.tokenProtection.isEnabled = true."}
}

func checkGuestInviteRestricted(d *DetectorData) baselinePolicyEval {
	if d.AzureAuthorizationPolicy == nil {
		return baselinePolicyEval{status: "unknown", reason: "authorizationPolicy not collected."}
	}
	v := strings.ToLower(strings.TrimSpace(d.AzureAuthorizationPolicy.AllowInvitesFrom))
	if v == "" {
		return baselinePolicyEval{status: "unknown", reason: "allowInvitesFrom field absent."}
	}
	if v != "everyone" {
		return baselinePolicyEval{
			status: "enabled",
			evidence: &types.BaselinePolicyEvidence{
				PolicyType: "authorizationPolicy",
				Details:    fmt.Sprintf("allowInvitesFrom = %q (restricted).", v),
			},
		}
	}
	return baselinePolicyEval{status: "disabled", reason: "allowInvitesFrom = everyone (default — needs restriction)."}
}
