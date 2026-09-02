package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Phase D detectors — additional ANSSI PA-099 controls implemented in v3.1.18.
//
// Each detector below targets one or two PA-099 R-codes that became auditable
// after the v3.1.18 collector extensions:
//   R36   — Address risks of certificate authorities affecting Tier 0
//   R49   — Address centralized management agents categorization
//   R50   — Address threat protection solutions categorization
//   R59   — Restrict security policies on Tier 0 OU
//   R79   — Harden remote connection clients (RDP encryption)
//   R82   — Restrict access to less trusted resources from Tier 0
//   R83   — Restrict authorized connection accounts for display redirection
//   R86   — Ensure segregation of any administration forest deployed
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf

// --- R36: CA risks affecting Tier 0 ---
//
// We approximate "Tier 0 CA risk" by flagging templates that issue certs
// usable for AD authentication AND that any of the v3.1.18 R37 weakness
// patterns apply to AND that have low-bar enrollment (RequiresManagerApproval=false).
// A CA publishing such templates is the single biggest Tier 0 PKI risk.

type R36CARisksDetector struct{ audit.BaseDetector }

func NewR36CARisksDetector() *R36CARisksDetector {
	return &R36CARisksDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R36_CA_RISKS", audit.CategoryCompliance),
	}
}

// caCertExpiryWarnDays = a CA signing cert that expires soon must be
// renewed urgently — a lapsed CA breaks every cert-based authentication
// path. ANSSI R36 doesn't fix a number; 90 days gives the org time to
// rotate without operational pressure.
const caCertExpiryWarnDays = 90

// weakSigAlgs marks CA signing algorithms ANSSI considers obsolete for
// Tier 0 use (collision risks against modern attackers).
var weakSigAlgs = map[string]bool{
	"SHA1-RSA":   true,
	"SHA1-ECDSA": true,
	"MD5-RSA":    true,
	"DSA-SHA1":   true,
}

func (d *R36CARisksDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.19 — enriched check: combines CA-level signals (signing cert weak,
	// expiry imminent, weak ACL on CA object) with template-level signals
	// (ESC1 / AnyPurpose / weak key length) from v3.1.18.
	now := data.Now
	expiryThreshold := now.AddDate(0, 0, caCertExpiryWarnDays)

	var caHits []string
	for _, ca := range data.CertAuthorities {
		var reasons []string
		if weakSigAlgs[ca.CACertSigAlg] {
			reasons = append(reasons, "CA cert signed with "+ca.CACertSigAlg)
		}
		if !ca.CACertNotAfter.IsZero() && ca.CACertNotAfter.Before(expiryThreshold) {
			reasons = append(reasons, fmt.Sprintf("CA cert expires %s (< %d days)", ca.CACertNotAfter.Format("2006-01-02"), caCertExpiryWarnDays))
		}
		if ca.HasWeakACL {
			reasons = append(reasons, "weak ACL on CA object (non-admins can modify)")
		}
		if len(reasons) > 0 {
			caHits = append(caHits, ca.Name+": "+strings.Join(reasons, ", "))
		}
	}

	// Template-level check (v3.1.18 logic)
	var risky []types.CertTemplate
	for _, t := range data.CertTemplates {
		if !templateUsableForAuth(t) {
			continue
		}
		if t.RequiresManagerApproval {
			continue
		}
		if len(weaknessReasons(t)) == 0 {
			continue
		}
		risky = append(risky, t)
	}

	if len(risky) == 0 && len(caHits) == 0 {
		return nil
	}

	// Build description combining both signals.
	parts := []string{}
	if len(caHits) > 0 {
		parts = append(parts, fmt.Sprintf("%d CA(s) carry intrinsic risk: %s", len(caHits), strings.Join(caHits, "; ")))
	}
	if len(risky) > 0 {
		parts = append(parts, fmt.Sprintf("%d certificate template(s) match an ESC pattern (R37 weakness) and are published without manager approval", len(risky)))
	}

	var entities []types.AffectedEntity
	if data.IncludeDetails {
		for _, ca := range data.CertAuthorities {
			if weakSigAlgs[ca.CACertSigAlg] || (!ca.CACertNotAfter.IsZero() && ca.CACertNotAfter.Before(expiryThreshold)) || ca.HasWeakACL {
				entities = append(entities, types.AffectedEntity{Type: "ca", DN: ca.DN, Name: ca.Name})
			}
		}
		for _, t := range risky {
			entities = append(entities, types.AffectedEntity{Type: types.EntityTypeCertTemplate, DN: t.DN, Name: t.DisplayName})
		}
	}

	count := len(risky) + len(caHits)
	return wrapFinding(d, "ANSSI R36 — Certificate authority risks affecting Tier 0",
		strings.Join(parts, ". ")+". ANSSI R36 requires addressing CA-level risks before they enable attackers to mint Tier 0 credentials. Renew expiring/SHA-1 CA certs, lock down CA ACLs, restrict risky templates (approval, remove ESC patterns).",
		types.SeverityHigh, count, entities)
}

// --- R49 + R50: management agents and threat protection categorization ---

// mgmtAgentMarkers identifies common centralized management endpoints by
// hostname or OS string. These should live in a dedicated tier (Tier 0 or
// Tier 1 depending on scope) per ANSSI R49/R50.
var mgmtAgentMarkers = []string{
	"sccm", "configmgr", "wsus", "mecm",
	"defender", "atp", "mdatp",
	"intune",
	"jamf",
	"ansible", "salt",
	"puppet", "chef",
	"tanium",
	"bigfix",
	"crowdstrike", "carbonblack", "sentinelone",
}

type R49R50MgmtCategorizationDetector struct{ audit.BaseDetector }

func NewR49R50MgmtCategorizationDetector() *R49R50MgmtCategorizationDetector {
	return &R49R50MgmtCategorizationDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R49_R50_MGMT_CATEGORIZATION", audit.CategoryCompliance),
	}
}

func (d *R49R50MgmtCategorizationDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.19 — set of explicit mgmt-system DNs from tier0_groups.yaml.
	customMgmt := map[string]bool{}
	if data.Tier0Config != nil {
		for _, dn := range data.Tier0Config.MgmtSystems {
			customMgmt[strings.ToLower(strings.TrimSpace(dn))] = true
		}
	}

	var unsorted []types.Computer
	for _, c := range data.Computers {
		host := strings.ToLower(c.SAMAccountName + " " + c.DNSHostName + " " + c.Description + " " + c.OperatingSystem)
		matches := customMgmt[strings.ToLower(c.DN)]
		if !matches {
			for _, m := range mgmtAgentMarkers {
				if strings.Contains(host, m) {
					matches = true
					break
				}
			}
		}
		if !matches {
			continue
		}
		// Flag if the computer DN does not contain a Tier-bearing OU marker.
		dn := strings.ToLower(c.DN)
		if strings.Contains(dn, "ou=tier0") || strings.Contains(dn, "ou=tier-0") ||
			strings.Contains(dn, "ou=tier1") || strings.Contains(dn, "ou=tier-1") ||
			strings.Contains(dn, "ou=admin") || strings.Contains(dn, "ou=mgmt") ||
			strings.Contains(dn, "ou=management") {
			continue
		}
		unsorted = append(unsorted, c)
	}
	if len(unsorted) == 0 {
		return nil
	}
	return wrapFinding(d, "ANSSI R49+R50 — Management agents not categorized into a dedicated Tier OU",
		fmt.Sprintf("%d computer(s) match centralized-management heuristics (SCCM/WSUS/Defender/Intune/...) but live outside any Tier 0/Tier 1/admin OU. ", len(unsorted))+
			"ANSSI R49 + R50 require categorization of management infrastructure: place these systems into a dedicated OU and apply the corresponding tier-segregated GPOs/ACLs.",
		types.SeverityMedium, len(unsorted), computersToEntities(unsorted, data.IncludeDetails))
}

// --- R59: Restrict security policies on Tier 0 OU ---

type R59Tier0OUPoliciesDetector struct{ audit.BaseDetector }

func NewR59Tier0OUPoliciesDetector() *R59Tier0OUPoliciesDetector {
	return &R59Tier0OUPoliciesDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R59_TIER0_OU_POLICIES", audit.CategoryCompliance),
	}
}

// tier0OUMarkersDN is intentionally narrow to avoid false positives on
// generic "Admin" OUs that are not Tier 0 in the strict sense.
var tier0OUMarkersDN = []string{
	"ou=tier0", "ou=tier-0", "ou=tier 0", "ou=t0", "ou=tier_0", "ou=paw",
}

func (d *R59Tier0OUPoliciesDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.19 — extra Tier 0 OU DNs from tier0_groups.yaml.
	customOUs := map[string]bool{}
	if data.Tier0Config != nil {
		for _, dn := range data.Tier0Config.OUs {
			customOUs[strings.ToLower(strings.TrimSpace(dn))] = true
		}
	}

	// Find Tier 0 OUs.
	var tier0OUs []types.OU
	for _, ou := range data.OUs {
		dn := strings.ToLower(ou.DN)
		matched := customOUs[dn]
		if !matched {
			for _, m := range tier0OUMarkersDN {
				if strings.Contains(dn, m) {
					matched = true
					break
				}
			}
		}
		if matched {
			tier0OUs = append(tier0OUs, ou)
		}
	}
	if len(tier0OUs) == 0 {
		// No Tier 0 OU detected — the org may not have one. Don't emit a
		// false positive; this control only makes sense when Tier 0 OU exists.
		return nil
	}
	// Build a map GPO GUID → GPO with weak ACL (HasWeakACL flag from collector).
	weakGPOs := map[string]types.GPO{}
	for _, g := range data.GPOs {
		if g.HasWeakACL {
			weakGPOs[strings.ToLower(g.GUID)] = g
		}
	}
	if len(weakGPOs) == 0 {
		return nil // no weak GPO → R59 is satisfied (nothing risky linked anywhere)
	}
	// Walk GPOLinks and flag links of weak GPOs to Tier 0 OUs.
	tier0DNSet := map[string]bool{}
	for _, ou := range tier0OUs {
		tier0DNSet[strings.ToLower(ou.DN)] = true
	}
	var hits []string
	for _, link := range data.GPOLinks {
		if !link.LinkEnabled || link.Disabled {
			continue
		}
		ref := strings.ToLower(link.GPOCN)
		if ref == "" {
			ref = strings.ToLower(link.GPOGuid)
		}
		// Match GPO by GUID substring against weakGPOs map.
		matched := false
		for guid := range weakGPOs {
			if guid != "" && strings.Contains(ref, guid) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if tier0DNSet[strings.ToLower(link.LinkedTo)] {
			hits = append(hits, fmt.Sprintf("GPO link %s → %s", link.GPOCN, link.LinkedTo))
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return wrapFinding(d, "ANSSI R59 — Weak-ACL GPO linked to a Tier 0 OU",
		fmt.Sprintf("%d GPO link(s) attach a GPO with a weak ACL (writable by non-admins) to a Tier 0 OU: %s. ", len(hits), strings.Join(hits, "; "))+
			"ANSSI R59 requires restricting security policies applicable to Tier 0 OUs — a low-trust user with write access on a linked GPO can pivot to Tier 0 by editing the policy.",
		types.SeverityCritical, len(hits), nil)
}

// --- R79: RDP encryption hardening ---

type R79RDPHardenedDetector struct{ audit.BaseDetector }

func NewR79RDPHardenedDetector() *R79RDPHardenedDetector {
	return &R79RDPHardenedDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R79_RDP_NOT_HARDENED", audit.CategoryCompliance),
	}
}

func (d *R79RDPHardenedDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	highEnc := false
	rpcEnc := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.RDPMinEncryptionLevel != nil && *p.RegistrySettings.RDPMinEncryptionLevel >= 3 {
			highEnc = true
		}
		if p.RegistrySettings.RDPEncryptRPCTraffic != nil && *p.RegistrySettings.RDPEncryptRPCTraffic >= 1 {
			rpcEnc = true
		}
	}
	if highEnc && rpcEnc {
		return nil
	}
	missing := []string{}
	if !highEnc {
		missing = append(missing, "Terminal Services\\MinEncryptionLevel ≥ 3 (high)")
	}
	if !rpcEnc {
		missing = append(missing, "Terminal Services\\fEncryptRPCTraffic = 1")
	}
	return wrapFinding(d, "ANSSI R79 — Remote Desktop client encryption not hardened",
		"ANSSI R79 requires hardening remote connection clients. Missing GPO setting(s): "+strings.Join(missing, "; ")+". Without forced high encryption + RPC traffic encryption, RDP sessions remain attackable from a network position (downgrade attacks, MITM).",
		types.SeverityMedium, 1, nil)
}

// --- R82 + R83: Restrict access from less-trusted accounts to Tier 0 ---
//
// R82 → SeDenyNetworkLogonRight + SeDenyInteractiveLogonRight must include
//       non-Tier-0 accounts (typically "Authenticated Users" or "Domain Users").
// R83 → SeDenyRemoteInteractiveLogonRight + SeRemoteInteractiveLogonRight
//       (display redirection) — RDP must NOT be allowed for low-trust users
//       on Tier 0 systems.

type R82R83AdminArchitectureDetector struct{ audit.BaseDetector }

func NewR82R83AdminArchitectureDetector() *R82R83AdminArchitectureDetector {
	return &R82R83AdminArchitectureDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R82_R83_ADMIN_ARCHITECTURE", audit.CategoryCompliance),
	}
}

// commonNonTier0SIDs are well-known SIDs that should appear in SeDeny*Right
// per ANSSI R82/R83 — denying them is the canonical way to ensure Tier 0
// accepts only Tier 0 accounts.
var commonNonTier0SIDs = []string{
	"S-1-5-7",             // Anonymous Logon
	"S-1-1-0",             // Everyone
	"S-1-5-11",            // Authenticated Users
	"S-1-5-32-545",        // BUILTIN\Users
	"S-1-5-32-546",        // BUILTIN\Guests
	"S-1-5-21-domain-513", // Domain Users (template; matched by suffix)
}

func (d *R82R83AdminArchitectureDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	denyNetwork := false
	denyRemote := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.PrivilegeRights == nil {
			continue
		}
		pr := p.PrivilegeRights
		if containsAnyNonTier0SID(pr.SeDenyNetworkLogonRight) ||
			containsAnyNonTier0SID(pr.SeDenyInteractiveLogonRight) {
			denyNetwork = true
		}
		if containsAnyNonTier0SID(pr.SeDenyRemoteInteractiveLogonRight) {
			denyRemote = true
		}
	}
	if denyNetwork && denyRemote {
		return nil
	}
	missing := []string{}
	if !denyNetwork {
		missing = append(missing, "SeDenyNetworkLogonRight / SeDenyInteractiveLogonRight (R82)")
	}
	if !denyRemote {
		missing = append(missing, "SeDenyRemoteInteractiveLogonRight (R83)")
	}
	return wrapFinding(d, "ANSSI R82+R83 — Tier 0 systems do not deny low-trust account logons",
		"ANSSI R82 + R83 require Tier 0 systems to refuse logon (network, interactive, RDP) from non-Tier-0 accounts (Domain Users, Authenticated Users, etc.). No GPO sets the corresponding deny privileges with such SIDs: "+strings.Join(missing, "; ")+". Add these SIDs to SeDeny*Right via Group Policy on the Tier 0 OU.",
		types.SeverityHigh, 1, nil)
}

func containsAnyNonTier0SID(sids []string) bool {
	for _, sid := range sids {
		clean := strings.TrimPrefix(strings.TrimSpace(sid), "*")
		// Domain Users RID 513 — match by suffix
		if strings.HasSuffix(clean, "-513") {
			return true
		}
		for _, target := range commonNonTier0SIDs {
			if strings.EqualFold(clean, target) {
				return true
			}
		}
	}
	return false
}

// --- R86: Admin forest segregation ---

type R86AdminForestSegregationDetector struct{ audit.BaseDetector }

func NewR86AdminForestSegregationDetector() *R86AdminForestSegregationDetector {
	return &R86AdminForestSegregationDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R86_ADMIN_FOREST_SEGREGATION", audit.CategoryCompliance),
	}
}

// adminForestNameMarkers identifies trusts whose target is likely an
// administration forest (ESAE / Red Forest / PAW forest).
var adminForestNameMarkers = []string{"admin", "esae", "red", "paw", "tier0", "t0"}

func (d *R86AdminForestSegregationDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.Trusts) == 0 {
		return nil
	}
	// v3.1.19 — extra admin-forest DNS suffixes from tier0_groups.yaml.
	customDNS := []string{}
	if data.Tier0Config != nil {
		for _, dn := range data.Tier0Config.AdminForestDNS {
			if d := strings.ToLower(strings.TrimSpace(dn)); d != "" {
				customDNS = append(customDNS, d)
			}
		}
	}

	var weak []types.Trust
	for _, t := range data.Trusts {
		name := strings.ToLower(t.TargetDomain)
		isAdminForest := false
		for _, m := range adminForestNameMarkers {
			if strings.Contains(name, m) {
				isAdminForest = true
				break
			}
		}
		if !isAdminForest {
			for _, dns := range customDNS {
				if strings.Contains(name, dns) {
					isAdminForest = true
					break
				}
			}
		}
		if !isAdminForest {
			continue
		}
		// Hardening required: SID filtering ON + selective auth ON + AES allowed
		if !t.SIDFiltering || !t.SelectiveAuth {
			weak = append(weak, t)
		}
	}
	if len(weak) == 0 {
		return nil
	}
	var entities []types.AffectedEntity
	if data.IncludeDetails {
		for _, t := range weak {
			entities = append(entities, types.AffectedEntity{Type: "trust", Name: t.TargetDomain})
		}
	}
	return wrapFinding(d, "ANSSI R86 — Administration forest trust not properly segregated",
		fmt.Sprintf("%d trust(s) target what looks like an administration forest (name contains %s) but lack SID filtering and/or selective authentication. ",
			len(weak), strings.Join(adminForestNameMarkers, "/"))+
			"ANSSI R86 requires segregation of any administration forest deployed: enable SID filtering (quarantine) AND selective authentication on the trust, otherwise the admin forest's privileged accounts are not properly isolated from the production forest.",
		types.SeverityHigh, len(weak), entities)
}

func init() {
	audit.MustRegister(NewR36CARisksDetector())
	audit.MustRegister(NewR49R50MgmtCategorizationDetector())
	audit.MustRegister(NewR59Tier0OUPoliciesDetector())
	audit.MustRegister(NewR79RDPHardenedDetector())
	audit.MustRegister(NewR82R83AdminArchitectureDetector())
	audit.MustRegister(NewR86AdminForestSegregationDetector())

	// helpers package import required for build (used by other detectors).
	_ = helpers.DefaultTier0AdminGroupNames
}
