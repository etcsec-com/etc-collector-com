package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R27: Kerberos pre-auth FAST armoring ---

type R27KerberosFASTArmoringDetector struct{ audit.BaseDetector }

func NewR27KerberosFASTArmoringDetector() *R27KerberosFASTArmoringDetector {
	return &R27KerberosFASTArmoringDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R27_KERBEROS_PREAUTH_NOT_FAST", audit.CategoryCompliance)}
}
func (d *R27KerberosFASTArmoringDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	dc, client := false, false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.KerberosArmoringDC != nil && *p.RegistrySettings.KerberosArmoringDC >= 1 {
			dc = true
		}
		if p.RegistrySettings.KerberosArmoringClient != nil && *p.RegistrySettings.KerberosArmoringClient >= 1 {
			client = true
		}
	}
	count := 0
	if !dc || !client {
		count = 1
	}
	// Domain-wide GPO fact (same nature as LAPS_NOT_DEPLOYED, which
	// already points AffectedEntities at the domain object rather than a
	// per-machine list); previously always nil (motif(c)).
	var entities []types.AffectedEntity
	if count == 1 && data.IncludeDetails && data.DomainInfo != nil && data.DomainInfo.DomainDN != "" {
		entities = []types.AffectedEntity{data.EntityForDN(data.DomainInfo.DomainDN)}
	}
	// ANSSI PA-099 (full-text source audit) R68 (p.93-94), "Activer le
	// blindage Kerberos sur les systèmes du Tier 0", requires BOTH:
	//  - client-side, GPO path Configuration ordinateur\Modèles
	//    d'administration\Système\Kerberos, "Prise en charge du client
	//    Kerberos pour les revendications, l'authentification composée et
	//    le blindage Kerberos: Activé" - parsed into KerberosArmoringClient
	//    (registrypol_parser.go: RequireFast);
	//  - DC-side, GPO path ...\Système\KDC, "Prise en charge du contrôleur
	//    de domaine Kerberos pour les revendications...: Activé avec la
	//    valeur 'Pris en charge'" - the real GPO value name is
	//    EnableCbacAndArmor under a Kdc-shaped key, parsed into
	//    KerberosArmoringDC. (The real R27 in PA-099 is unrelated: regularly
	//    running AD control-path analysis tools, e.g. BloodHound, p.43.)
	return wrapFinding(d, "ANSSI PA-099 R68 - Blindage Kerberos (FAST) non activé sur le Tier 0",
		"ANSSI PA-099 R68 (p.93-94) requires Kerberos armoring (\"blindage Kerberos\", RFC 6113 FAST) enabled on Tier 0 systems, both client-side (EnableCbacAndArmor / RequireFast) and DC-side (KDC EnableCbacAndArmor).",
		types.SeverityMedium, count, entities)
}

func init() {
	audit.MustRegister(NewR27KerberosFASTArmoringDetector())
}
