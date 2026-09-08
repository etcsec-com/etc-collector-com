package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Phase D detectors - additional ANSSI PA-099 controls implemented in v3.1.18.
//
// Each detector below targets one or two PA-099 R-codes that became auditable
// after the v3.1.18 collector extensions:
// R36   - Address risks of certificate authorities affecting Tier 0
// R49   - Address centralized management agents categorization
// R50   - Address threat protection solutions categorization
// R59   - Restrict security policies on Tier 0 OU
// R79   - Harden remote connection clients (RDP encryption)
// R82   - Restrict access to less trusted resources from Tier 0
// R83   - Restrict authorized connection accounts for display redirection
// R86   - Ensure segregation of any administration forest deployed
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
// renewed urgently - a lapsed CA breaks every cert-based authentication
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
	// v3.1.19 - enriched check: combines CA-level signals (signing cert weak,
	// expiry imminent, weak ACL on CA object) with template-level signals
	// (ESC1 / AnyPurpose / weak key length) from v3.1.18.
	now := data.Now
	expiryThreshold := now.AddDate(0, 0, caCertExpiryWarnDays)

	// CA DNs now enter collectData's objectDNs batch
	// (internal/audit/engine.go, shared core), so
	// per-CA ACEs land in data.ACLEntries alongside every other object type.
	// CertAuthority.HasWeakACL itself stays unassigned (same read-time-not-
	// write-time choice  made for GPO.HasWeakACL): computed here via
	// WeakACLCADNs from data.ACLEntries instead of a collector-mutated
	// field, since detectors run concurrently once collectData returns and
	// mutating a shared struct from here would race.
	weakCADNs := audit.WeakACLCADNs(data)
	var caHits []string
	for _, ca := range data.CertAuthorities {
		var reasons []string
		if weakSigAlgs[ca.CACertSigAlg] {
			reasons = append(reasons, "CA cert signed with "+ca.CACertSigAlg)
		}
		if !ca.CACertNotAfter.IsZero() && ca.CACertNotAfter.Before(expiryThreshold) {
			reasons = append(reasons, fmt.Sprintf("CA cert expires %s (< %d days)", ca.CACertNotAfter.Format("2006-01-02"), caCertExpiryWarnDays))
		}
		if weakCADNs[strings.ToLower(ca.DN)] {
			reasons = append(reasons, "weak ACL on CA object (non-admins can modify)")
		}
		if len(reasons) > 0 {
			caHits = append(caHits, ca.Name+": "+strings.Join(reasons, ", "))
		}
	}

	// Template-level check (v3.1.18 logic)
	weakACLDNs := audit.WeakACLTemplateDNs(data)
	var risky []types.CertTemplate
	for _, t := range data.CertTemplates {
		if !templateUsableForAuth(t) {
			continue
		}
		if t.RequiresManagerApproval {
			continue
		}
		if len(weaknessReasons(t, weakACLDNs[strings.ToLower(t.DN)])) == 0 {
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
			if weakSigAlgs[ca.CACertSigAlg] || (!ca.CACertNotAfter.IsZero() && ca.CACertNotAfter.Before(expiryThreshold)) || weakCADNs[strings.ToLower(ca.DN)] {
				entities = append(entities, types.AffectedEntity{Type: "ca", DN: ca.DN, Name: ca.Name})
			}
		}
		for _, t := range risky {
			entities = append(entities, types.AffectedEntity{Type: types.EntityTypeCertTemplate, DN: t.DN, Name: t.DisplayName})
		}
	}

	count := len(risky) + len(caHits)
	return wrapFinding(d, "ANSSI R36 - Certificate authority risks affecting Tier 0",
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
	// v3.1.19 - set of explicit mgmt-system DNs from tier0_groups.yaml.
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
	return wrapFinding(d, "ANSSI R49+R50 - Management agents not categorized into a dedicated Tier OU",
		fmt.Sprintf("%d computer(s) match centralized-management heuristics (SCCM/WSUS/Defender/Intune/...) but live outside any Tier 0/Tier 1/admin OU. ", len(unsorted))+
			"ANSSI R49 (p.62-63) + R50 (p.64) require categorization of management infrastructure: place these systems into a dedicated OU and apply the corresponding tier-segregated GPOs/ACLs. "+
			"HEURISTIC ONLY, on both signals: matching is by hostname/OS/description keyword and by an OU-name marker, an architectural control that isn't literally encoded anywhere in AD. A real management server with none of the mgmtAgentMarkers substrings in its name/description (custom or renamed product) is a false negative - R49/R50 do not fire for it even if it's genuinely miscategorized. Conversely, a correctly-tiered management server whose OU simply doesn't contain a recognized tier-name marker (e.g. a customer's own naming convention) is a false positive - flagged here despite being properly segregated in practice.",
		types.SeverityMedium, len(unsorted), computersToEntities(unsorted, data.IncludeDetails))
}

// --- R59: Restrict security policies on Tier 0 OU ---
//
// R59 (p.74) actually has THREE components:
// 1. the Tier 0 OU must block GPO inheritance from parent OUs/domain root
// (gPOptions) - NOT collected yet (see pkg/types/finding.go's
// blockInheritance comment: "gPOptions not threaded yet"), so this
// detector cannot check it and must not claim to.
// 2. the Default Domain Policy must still be explicitly linked to the
// Tier 0 OU, with the lowest priority - checkable in principle
// (GPOLink.Order/Enforced exist), but ONLY meaningful once (1) is
// known to be true: on a domain that does NOT block inheritance,
// Default Domain Policy correctly reaching the Tier 0 OU via normal
// inheritance, unlinked, is fine. Emitting a finding here without
// knowing (1) would manufacture a new false positive of exactly the
// kind this work exists to remove - left unimplemented for that
// reason, not because the data is unreachable.
// 3. GPOs linked/applied to the Tier 0 OU must be dedicated to Tier 0 and
// modifiable only by Tier 0 admins - the ACL check below. This is the
// ONLY one of the three this detector measures.
//
// Title/description are written to say exactly that, instead of claiming
// full R59 coverage.

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
	// v3.1.19 - extra Tier 0 OU DNs from tier0_groups.yaml.
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
		// No Tier 0 OU detected - the org may not have one. Don't emit a
		// false positive; this control only makes sense when Tier 0 OU exists.
		return nil
	}
	// Build a map GPO GUID → GPO with weak ACL. GPO.HasWeakACL was
	// never assigned by the collector; computed here instead from
	// data.GPOAcls via the dangerousMask convention (see WeakACLGPODNs).
	weakGPODNs := audit.WeakACLGPODNs(data)
	weakGPOs := map[string]types.GPO{}
	for _, g := range data.GPOs {
		if weakGPODNs[strings.ToLower(g.DN)] {
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
	return wrapFinding(d, "ANSSI R59 (partial) - Weak-ACL GPO linked to a Tier 0 OU",
		fmt.Sprintf("%d GPO link(s) attach a GPO with a weak ACL (writable by non-admins) to a Tier 0 OU: %s. ", len(hits), strings.Join(hits, "; "))+
			"ANSSI R59 requires GPOs linked to the Tier 0 OU to be dedicated and admin-only-modifiable - this is the ONE of R59's three components this check covers. It does NOT verify that the Tier 0 OU blocks GPO inheritance, nor that the Default Domain Policy is relinked to it at the lowest priority (both required by R59, neither observable with currently-collected data). A low-trust user with write access on a linked GPO can pivot to Tier 0 by editing the policy.",
		types.SeverityCritical, len(hits), nil)
}

// --- RDP server-side encryption hardening (NOT ANSSI R79 - see below) ---
//
// This detector's title/description used to claim ANSSI R79. Checked against
// R79's full text (p.104-105): "Durcir les clients de connexion distante
// dont les politiques de sécurité autorisent l'usage" - R79 is about
// hardening the RDP CLIENT application (disable hardware graphics
// acceleration, restrict clipboard redirection, restrict smart-card
// redirection to when actually needed). It is not, in any part, about the
// server-side Terminal Services encryption level or RPC traffic encryption
// checked below. None of R79's actual required settings are currently
// collected (no RegistrySettings field exists for RDP graphics acceleration
// or clipboard redirection), so this detector cannot measure R79 and must
// not claim to. The detector ID (ANSSI_R79_RDP_NOT_HARDENED) and the
// mappings.go framework tag for it are unchanged here - both are out of
// scope here (internal/audit/compliance/mappings.go);
// noted as a needed follow-up, same as R82/R83 below.
//
// Server-side RDP encryption hardening (MinEncryptionLevel, RPC traffic
// encryption) is a legitimate, independent hardening measure in its own
// right - it's just not R79. No ANSSI attribution is made below.

type R79RDPHardenedDetector struct{ audit.BaseDetector }

func NewR79RDPHardenedDetector() *R79RDPHardenedDetector {
	return &R79RDPHardenedDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R79_RDP_NOT_HARDENED", audit.CategoryCompliance),
	}
}

func (d *R79RDPHardenedDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// If no GPO carries any RegistrySettings at all (SMB/SYSVOL wasn't
	// collected, or no Registry.pol was found), both signals below stay
	// false by construction and the detector previously reported a
	// guaranteed false positive ("not hardened") indistinguishable from a
	// real violation. Mirrors the R4/R13 fix in r4-logging.go:
	// absence of evidence is not evidence of a violation.
	sawAnyRegistrySettings := false
	highEnc := false
	rpcEnc := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		sawAnyRegistrySettings = true
		if p.RegistrySettings.RDPMinEncryptionLevel != nil && *p.RegistrySettings.RDPMinEncryptionLevel >= 3 {
			highEnc = true
		}
		if p.RegistrySettings.RDPEncryptRPCTraffic != nil && *p.RegistrySettings.RDPEncryptRPCTraffic >= 1 {
			rpcEnc = true
		}
	}
	if !sawAnyRegistrySettings {
		return nil
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
	return wrapFinding(d, "Remote Desktop server-side encryption not hardened",
		"Missing GPO setting(s): "+strings.Join(missing, "; ")+". Without forced high encryption + RPC traffic encryption, RDP sessions remain attackable from a network position (downgrade attacks, MITM). This is NOT a measurement of ANSSI R79 (client-side hardening: graphics acceleration, clipboard/smart-card redirection - none of which is currently collected); it is a separate, independent RDP hardening baseline.",
		types.SeverityMedium, 1, nil)
}

// --- Tier 0 deny-logon hardening (NOT ANSSI R82/R83 - see below) ---
//
// this detector's title/description used to claim it measures
// ANSSI R82 + R83. Checked against the full body text of both (p.111):
//
// R82 = "Restreindre l'accès aux ressources de zones de moindre confiance
// depuis le Tier 0" - restricts which OUTBOUND connection methods a Tier 0
// admin may use to reach a LOWER-trust zone (RPC/MMC, WinRM with default
// auth, or native RDP with RestrictedAdmin / a lower-tier account). It is
// about egress FROM Tier 0, the opposite direction of what's checked here
// (denying INBOUND logon TO Tier 0 FROM low-trust accounts).
//
// R83 = "Restreindre les comptes de connexion autorisés pour le déport
// d'affichage" - on that same egress display-redirection session, the
// account used on the lower-trust REMOTE system must belong to that
// system's own trust tier, not a higher one. Also an egress-direction
// control. The guide's own footnote 46 states explicitly that
// "stratégies de sécurité pour la restriction d'ouverture de session"
// (i.e. exactly the SeDeny*LogonRight GPO settings checked below) are
// "not sufficient to apply R83, unless NTLM authentication is also
// forbidden" on the target systems/accounts.
//
// Denying network/interactive/remote-interactive logon on Tier 0 systems to
// non-Tier-0 SIDs is a legitimate, independent Tier-0 hardening measure -
// it's just not what R82 or R83 specify, and the guide itself says this
// technique alone can't satisfy R83. No ANSSI attribution is made below.
// The detector ID (ANSSI_R82_R83_ADMIN_ARCHITECTURE) and the mappings.go
// framework tags for it are unchanged here - both are out of scope
// here (internal/audit/compliance/mappings.go); noted as a follow-up
// as a needed follow-up.

type R82R83AdminArchitectureDetector struct{ audit.BaseDetector }

func NewR82R83AdminArchitectureDetector() *R82R83AdminArchitectureDetector {
	return &R82R83AdminArchitectureDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R82_R83_ADMIN_ARCHITECTURE", audit.CategoryCompliance),
	}
}

// commonNonTier0SIDs are well-known SIDs that should appear in SeDeny*Right
// per ANSSI R82/R83 - denying them is the canonical way to ensure Tier 0
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
		missing = append(missing, "SeDenyNetworkLogonRight / SeDenyInteractiveLogonRight")
	}
	if !denyRemote {
		missing = append(missing, "SeDenyRemoteInteractiveLogonRight")
	}
	return wrapFinding(d, "Tier 0 systems do not deny low-trust account logons",
		"Tier 0 systems should refuse logon (network, interactive, RDP) from non-Tier-0 accounts (Domain Users, Authenticated Users, etc.) as a hardening baseline. No GPO sets the corresponding deny privileges with such SIDs: "+strings.Join(missing, "; ")+". This is NOT a measurement of ANSSI R82 or R83 (both are about restricting Tier 0's OUTBOUND connections to less-trusted zones, the opposite direction, and the guide's own footnote on R83 says deny-logon GPO settings alone don't satisfy it). Add these SIDs to SeDeny*Right via Group Policy on the Tier 0 OU as a defense-in-depth measure regardless.",
		types.SeverityHigh, 1, nil)
}

func containsAnyNonTier0SID(sids []string) bool {
	for _, sid := range sids {
		clean := strings.TrimPrefix(strings.TrimSpace(sid), "*")
		// Domain Users RID 513 - match by suffix
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
//
// Bare "red" and "t0" were removed - both are common English-word/
// abbreviation substrings with a high false-positive rate (e.g. "red"
// matches "shared.corp.local" or "credentials.corp.local"; "t0" matches
// "test01.corp.local" via its "st0" substring). This heuristic was never
// observed to fire in practice, so the false-positive risk was untested;
// the replacements below require the Red-Forest / Tier-0 token to appear as
// a more distinctive, delimited label instead of a bare 2-3 letter substring.
var adminForestNameMarkers = []string{"admin", "esae", "redforest", "red-forest", "paw", "tier0", "tier-0", "-t0", "t0-"}

func (d *R86AdminForestSegregationDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.Trusts) == 0 {
		return nil
	}
	// v3.1.19 - extra admin-forest DNS suffixes from tier0_groups.yaml.
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
	return wrapFinding(d, "ANSSI R86 - Administration forest trust not properly segregated",
		fmt.Sprintf("%d trust(s) target what looks like an administration forest (name contains %s) but lack SID filtering and/or selective authentication. ",
			len(weak), strings.Join(adminForestNameMarkers, "/"))+
			"ANSSI R86 (p.116) requires segregation of any administration forest deployed, applying section 3.2.3's outbound-trust hardening (R24, p.40) to the relation between the admin forest and the forests it administers: forest-type trusts must not use SID history (no TREAT_AS_EXTERNAL), external/domain-type trusts must be quarantined (QUARANTINED_DOMAIN), plus selective authentication. CAVEAT: this detector only has a single generic SIDFiltering boolean per trust, not the underlying trust-attribute bitmask - R24 prescribes a DIFFERENT bit per trust type (TREAT_AS_EXTERNAL for Forest trusts vs. QUARANTINED_DOMAIN for External trusts). If SIDFiltering is wired to only one of those bits, a correctly-hardened trust of the other type could be a false positive here; this has never been observed to fire, so the mapping is unverified.",
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
