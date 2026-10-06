package lifecycle

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDDisabledNotBlocked       = "USER_DISABLED_NOT_BLOCKED"
	CategoryDisabledNotBlocked = audit.CategoryIdentity
)

// DisabledNotBlockedDetector checks for disabled users not blocked from sign-in
type DisabledNotBlockedDetector struct {
	audit.BaseDetector
}

// NewUserDisabledNotBlockedDetector creates a new disabled not blocked detector
func NewUserDisabledNotBlockedDetector() *DisabledNotBlockedDetector {
	return &DisabledNotBlockedDetector{
		BaseDetector: audit.NewBaseDetector(IDDisabledNotBlocked, CategoryDisabledNotBlocked),
	}
}

// Detect finds disabled user accounts whose prior session/token revocation
// status this collector cannot confirm.
//
// The title deliberately does not say "not blocked from sign-in": per
// Microsoft Learn, "Revoke user access in an emergency in Microsoft Entra ID"
// (learn.microsoft.com/entra/identity/users/users-revoke-access, section
// "Microsoft Entra environment"), clearing accountEnabled DOES immediately
// block new sign-in attempts. What it does NOT do is revoke access/refresh
// tokens or session cookies already issued - that needs a separate action
// ("On the user Overview page, select Revoke sessions", i.e.
// Revoke-MgUserSignInSession, which resets signInSessionsValidFromDateTime).
// This collector reads accountEnabled (types.User.Disabled) but never
// signInSessionsValidFromDateTime - that field isn't collected - so it
// cannot tell a disabled user whose sessions were separately revoked from
// one who was only disabled. Every disabled user is reported here with that
// scope stated honestly, rather than under a title asserting they can still
// sign in - which disabling itself already prevents.
func (d *DisabledNotBlockedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:     IDDisabledNotBlocked,
		Severity: types.SeverityMedium,
		Category: string(CategoryDisabledNotBlocked),
		Title:    "Disabled Users With Session Revocation Not Confirmed",
		Description: "User accounts are disabled (new sign-in is already blocked), but this collector has no way to confirm " +
			"whether their existing sessions and refresh tokens were separately revoked (Microsoft Entra ID does not revoke " +
			"them automatically on disable). Run 'Revoke sessions' for each to close any window an already-issued token leaves open.",
		Count: 0,
	}

	var affected []types.User

	for _, user := range data.Users {
		if user.Disabled {
			affected = append(affected, user)
		}
	}

	finding.Count = len(affected)

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserDisabledNotBlockedDetector())
}
