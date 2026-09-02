package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-PA-099 R73 + R74+ — Block outbound NTLM traffic.
//
//   R73  — Bloquer le trafic NTLM sortant depuis les systèmes du Tier 0
//   R74+ — Bloquer le trafic NTLM sortant depuis tous les systèmes du SI
//          qui le permettent (renforcement)
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf
//
// Both controls map to the same registry value:
//   HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic
//   0 = Allow all, 1 = Audit, 2 = Deny all
//
// The distinction R73 vs R74+ is the SCOPE of the GPO:
//   R73   = applied to Tier 0 (DCs / Tier 0 OU)
//   R74+  = applied domain-wide to all systems
//
// Without GPO scope analysis (which OUs the GPO links to), we approximate:
//   - If at least one GPO sets RestrictSendingNTLMTraffic=2 ⇒ R73 met
//   - If at least 2 distinct GPOs set =2 (or one is the Default Domain
//     Policy) ⇒ R74+ met. Otherwise R74+ flagged as not met.

// --- R73: NTLM outbound not blocked on Tier 0 ---

type R73NTLMOutboundTier0Detector struct{ audit.BaseDetector }

func NewR73NTLMOutboundTier0Detector() *R73NTLMOutboundTier0Detector {
	return &R73NTLMOutboundTier0Detector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R73_NTLM_OUTBOUND_TIER0", audit.CategoryCompliance),
	}
}

func (d *R73NTLMOutboundTier0Detector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if gpoSetsAtLeast(data, func(rs *audit.RegistrySettings) *int { return rs.RestrictSendingNTLMTraffic }, 2) {
		return nil
	}
	// Audit-only mode (=1) is not enough — R73 prescribes "deny" on Tier 0.
	return wrapFinding(d, "ANSSI R73 — Outbound NTLM traffic not blocked on Tier 0",
		"ANSSI R73 requires Tier 0 systems (DCs, admin servers) to refuse outgoing NTLM authentication. No GPO sets Lsa\\MSV1_0\\RestrictSendingNTLMTraffic to 2 (Deny all). Without it, a compromised low-trust server can coerce a DC to NTLM-authenticate to it (PetitPotam, PrinterBug) and have its hash relayed.",
		types.SeverityHigh, 1, nil)
}

// --- R74+: NTLM outbound not blocked domain-wide ---

type R74NTLMOutboundDomainDetector struct{ audit.BaseDetector }

func NewR74NTLMOutboundDomainDetector() *R74NTLMOutboundDomainDetector {
	return &R74NTLMOutboundDomainDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R74_NTLM_OUTBOUND_DOMAIN", audit.CategoryCompliance),
	}
}

func (d *R74NTLMOutboundDomainDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.18 — exact scope analysis: a GPO with RestrictSendingNTLMTraffic=2
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
	return wrapFinding(d, "ANSSI R74+ — Outbound NTLM traffic not blocked domain-wide",
		"ANSSI R74+ (renforcement) extends R73 to ALL systems that can support it. No GPO with Lsa\\MSV1_0\\RestrictSendingNTLMTraffic=2 (Deny) is linked at the domain root, so most member servers/workstations still emit NTLM, sustaining the relay/coercion attack surface. Link the deny-NTLM-outbound GPO at the domain root (with appropriate exemption WMI filters for legacy systems).",
		types.SeverityLow, 1, nil)
}

func init() {
	audit.MustRegister(NewR73NTLMOutboundTier0Detector())
	audit.MustRegister(NewR74NTLMOutboundDomainDetector())
}
