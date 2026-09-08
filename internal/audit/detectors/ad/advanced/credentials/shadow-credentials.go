package credentials

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ShadowCredentialsDetector detects Shadow Credentials attack vectors
type ShadowCredentialsDetector struct {
	audit.BaseDetector
}

// NewShadowCredentialsDetector creates a new detector
func NewShadowCredentialsDetector() *ShadowCredentialsDetector {
	return &ShadowCredentialsDetector{
		BaseDetector: audit.NewBaseDetector("SHADOW_CREDENTIALS", audit.CategoryAdvanced),
	}
}

// Detect executes the detection.
//
// Coverage: both types.User and types.Computer carry msDS-KeyCredentialLink
// and are checked here. A computer account compromised via Shadow
// Credentials is, per Elad Shamir's original "Shadow Credentials" research
// and Microsoft's own guidance on msDS-KeyCredentialLink abuse, arguably the
// more consequential real-world vector - it hands an attacker a path to
// RBCD/S4U2Self abuse from the machine account, not just user impersonation.
// Only checking types.User (as this detector did previously) silently
// missed every computer-account instance of the technique.
//
// Presence-of-attribute caveat: a non-empty msDS-KeyCredentialLink is a
// PREREQUISITE for the attack (the attacker adds a key they control), not
// proof one was added by an attacker. A legitimate Windows Hello for
// Business (WHfB) deployment populates this attribute by design on every
// enrolled device and user. This detector can only see presence, not intent
// - treat a hit as "review this key credential," not "this account is
// compromised."
func (d *ShadowCredentialsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedUsers []types.User
	for _, u := range data.Users {
		if len(u.KeyCredentialLink) > 0 {
			affectedUsers = append(affectedUsers, u)
		}
	}

	var affectedComputers []types.Computer
	for _, c := range data.Computers {
		if len(c.KeyCredentialLink) > 0 {
			affectedComputers = append(affectedComputers, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Shadow Credentials",
		Description: "msDS-KeyCredentialLink is configured on a user or computer account. This is the prerequisite for a Shadow Credentials attack (Kerberos PKINIT authentication as the account via an attacker-controlled key) - it is not proof of compromise: Windows Hello for Business legitimately populates this attribute on every enrolled device and user. Review each entry to confirm the key credential is expected.",
		Count:       len(affectedUsers) + len(affectedComputers),
	}

	if data.IncludeDetails && (len(affectedUsers) > 0 || len(affectedComputers) > 0) {
		entities := make([]types.AffectedEntity, 0, len(affectedUsers)+len(affectedComputers))
		entities = append(entities, helpers.ToAffectedUserEntities(affectedUsers)...)
		entities = append(entities, helpers.ToAffectedComputerEntities(affectedComputers)...)
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewShadowCredentialsDetector())
}
