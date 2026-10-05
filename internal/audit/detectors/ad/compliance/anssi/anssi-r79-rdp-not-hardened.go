package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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
// noted as a needed follow-up, same as R82/R83 in
// anssi-r82-r83-admin-architecture.go.
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

func init() {
	audit.MustRegister(NewR79RDPHardenedDetector())
}
