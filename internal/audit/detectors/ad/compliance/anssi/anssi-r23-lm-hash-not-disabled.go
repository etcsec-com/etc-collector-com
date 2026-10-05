package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R23: LM hash storage must be disabled ---

type R23LMHashStorageDetector struct{ audit.BaseDetector }

func NewR23LMHashStorageDetector() *R23LMHashStorageDetector {
	return &R23LMHashStorageDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R23_LM_HASH_NOT_DISABLED", audit.CategoryCompliance)}
}
func (d *R23LMHashStorageDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit) R72 (p.97-98) mandates, via
	// GPO path "Configuration ordinateur\Paramètres Windows\Paramètres de
	// sécurité\Stratégies locales\Options de sécurité\Sécurité Réseau",
	// setting "Niveau d'authentification LAN Manager" to "Envoyer uniquement
	// une réponse NTLM version 2 et refuser LM et NTLM" - exactly
	// LmCompatibilityLevel=5. That is what this detector actually reads.
	// (The real R23 in PA-099 is unrelated: "Contrôler les permissions
	// appliquées aux comptes et groupes de Tier 0" - adminSDHolder/ACL
	// hygiene, p.40.) NoLMHash (SAM hash-storage suppression) is a distinct
	// Windows setting this guide never mentions; LmCompatibilityLevel
	// governs the LAN Manager authentication LEVEL, not hash storage, and
	// is used here only because it's the setting PA-099 R72 actually names.
	compliant := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.LmCompatibilityLevel != nil && *p.RegistrySettings.LmCompatibilityLevel >= 5 {
			compliant = true
			break
		}
	}
	count := 0
	if !compliant {
		count = 1
	}
	return wrapFinding(d, "ANSSI PA-099 R72 - Niveau d'authentification LAN Manager non durci",
		"ANSSI PA-099 R72 (p.97-98) requires \"Niveau d'authentification LAN Manager\" set to \"Envoyer uniquement une réponse NTLM version 2 et refuser LM et NTLM\" (LmCompatibilityLevel=5) on every AD-member system. Below level 5, legacy LM/NTLMv1 responses remain negotiable and are trivially crackable.",
		types.SeverityHigh, count, nil)
}

func init() {
	audit.MustRegister(NewR23LMHashStorageDetector())
}
