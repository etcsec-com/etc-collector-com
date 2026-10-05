package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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

func init() {
	audit.MustRegister(NewR82R83AdminArchitectureDetector())
}
