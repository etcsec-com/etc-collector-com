package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-PA-099 R73 + R74+ - Block outbound NTLM traffic.
//
// R73  - Bloquer le trafic NTLM sortant depuis les systèmes du Tier 0
// R74+ - Bloquer le trafic NTLM sortant depuis tous les systèmes du SI
// qui le permettent (renforcement)
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf
//
// Both controls map to the same registry value:
// HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic
// 0 = Allow all, 1 = Audit, 2 = Deny all
//
// The distinction R73 vs R74+ is the SCOPE of the GPO:
// R73   = applied to Tier 0 (DCs / Tier 0 OU) - R73's own text is explicit
// that the setting must apply "sur tous les systèmes du Tier 0"
// R74+  = applied domain-wide to all systems
//
// R73 previously matched on ANY GPO setting the registry value,
// anywhere, with zero link-scope check: a GPO linked to an unrelated OU
// satisfied it. That's a false negative factory - a domain where the
// setting is configured but never actually applied to Tier 0 read as
// compliant. R73 now requires the GPO to be link-enabled at the domain root
// (covers Tier 0 as a superset, same signal R74+ already used) OR linked to
// a Tier 0 OU. DCs themselves stay in the built-in "OU=Domain Controllers"
// container by design (PA-099 R58's own stated exception - DC computer
// accounts are never relocated into a custom Tier 0 OU), which
// helpers.isTier0OUDN's naming-marker heuristic doesn't recognize, so it's
// checked separately here alongside any tier0_groups.yaml custom OU.

// --- R73: NTLM outbound not blocked on Tier 0 ---

type R73NTLMOutboundTier0Detector struct{ audit.BaseDetector }

func NewR73NTLMOutboundTier0Detector() *R73NTLMOutboundTier0Detector {
	return &R73NTLMOutboundTier0Detector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R73_NTLM_OUTBOUND_TIER0", audit.CategoryCompliance),
	}
}

func (d *R73NTLMOutboundTier0Detector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	domainDN := ""
	if data.DomainInfo != nil {
		domainDN = data.DomainInfo.DomainDN
	}
	customTier0OUs := map[string]bool{}
	if data.Tier0Config != nil {
		for _, dn := range data.Tier0Config.OUs {
			customTier0OUs[strings.ToLower(strings.TrimSpace(dn))] = true
		}
	}
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil || p.RegistrySettings.RestrictSendingNTLMTraffic == nil {
			continue
		}
		// Audit-only mode (=1) is not enough - R73 prescribes "deny" on Tier 0.
		if *p.RegistrySettings.RestrictSendingNTLMTraffic < 2 {
			continue
		}
		scope := helpers.ComputeGPOScope(data, p.GUID, domainDN)
		if scope.LinkedToDomain || scope.LinkedTier0OU {
			return nil // R73 met - domain-wide covers Tier 0 as a superset; a Tier-0-OU link covers it directly
		}
		if gpoLinkedToAny(data, p.GUID, customTier0OUs, "ou=domain controllers") {
			return nil // R73 met - linked to the built-in DC container or a tier0_groups.yaml custom OU
		}
	}
	return wrapFinding(d, "ANSSI R73 - Outbound NTLM traffic not blocked on Tier 0",
		"ANSSI R73 requires Tier 0 systems (DCs, admin servers) to refuse outgoing NTLM authentication. No GPO sets Lsa\\MSV1_0\\RestrictSendingNTLMTraffic to 2 (Deny all) AND is actually linked (enabled) to Tier 0 - either the domain root, a Tier 0 OU, or the Domain Controllers container. A GPO with the right value that's linked elsewhere does not satisfy R73. Without it, a compromised low-trust server can coerce a DC to NTLM-authenticate to it (PetitPotam, PrinterBug) and have its hash relayed.",
		types.SeverityHigh, 1, nil)
}

// gpoLinkedToAny reports whether the GPO identified by guid has an
// enabled link whose target DN contains one of the given lowercase
// substrings, or matches one of the given lowercase full DNs.
func gpoLinkedToAny(data *audit.DetectorData, guid string, exactDNs map[string]bool, substrings ...string) bool {
	guidLower := strings.ToLower(guid)
	for _, link := range data.GPOLinks {
		if link.Disabled || !link.LinkEnabled {
			continue
		}
		ref := strings.ToLower(link.GPOCN)
		if ref == "" {
			ref = strings.ToLower(link.GPOGuid)
		}
		if !strings.Contains(ref, guidLower) {
			continue
		}
		target := strings.ToLower(link.LinkedTo)
		if exactDNs[target] {
			return true
		}
		for _, sub := range substrings {
			if strings.Contains(target, sub) {
				return true
			}
		}
	}
	return false
}

// --- R74+: NTLM outbound not blocked domain-wide ---

type R74NTLMOutboundDomainDetector struct{ audit.BaseDetector }

func NewR74NTLMOutboundDomainDetector() *R74NTLMOutboundDomainDetector {
	return &R74NTLMOutboundDomainDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R74_NTLM_OUTBOUND_DOMAIN", audit.CategoryCompliance),
	}
}

func (d *R74NTLMOutboundDomainDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.18 - exact scope analysis: a GPO with RestrictSendingNTLMTraffic=2
	// satisfies R74+ only when it's linked at the domain root (domainDN).
	// Counting GPOs (v3.1.17) was a heuristic; this is precise.
	domainDN := ""
	if data.DomainInfo != nil {
		domainDN = data.DomainInfo.DomainDN
	}
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.RestrictSendingNTLMTraffic == nil || *p.RegistrySettings.RestrictSendingNTLMTraffic < 2 {
			continue
		}
		scope := helpers.ComputeGPOScope(data, p.GUID, domainDN)
		if scope.LinkedToDomain {
			return nil // R74+ met
		}
	}
	return wrapFinding(d, "ANSSI R74+ - Outbound NTLM traffic not blocked domain-wide",
		"ANSSI R74+ (renforcement) extends R73 to ALL systems that can support it. No GPO with Lsa\\MSV1_0\\RestrictSendingNTLMTraffic=2 (Deny) is linked at the domain root, so most member servers/workstations still emit NTLM, sustaining the relay/coercion attack surface. Link the deny-NTLM-outbound GPO at the domain root (with appropriate exemption WMI filters for legacy systems).",
		types.SeverityLow, 1, nil)
}

func init() {
	audit.MustRegister(NewR73NTLMOutboundTier0Detector())
	audit.MustRegister(NewR74NTLMOutboundDomainDetector())
}
