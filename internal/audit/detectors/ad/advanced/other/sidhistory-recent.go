package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SIDHistoryRecentDetector checks for users with SIDHistory that were recently modified
type SIDHistoryRecentDetector struct {
	audit.BaseDetector
}

// NewSIDHistoryRecentDetector creates a new detector
func NewSIDHistoryRecentDetector() *SIDHistoryRecentDetector {
	return &SIDHistoryRecentDetector{
		BaseDetector: audit.NewBaseDetector("SIDHISTORY_RECENT_CHANGES", audit.CategoryAdvanced),
	}
}

// Detect executes the detection.
//
// Scope limitation, re-titled/re-described rather than silently
// misrepresented: Active Directory does not expose a per-attribute
// last-modified timestamp for sIDHistory over plain LDAP - whenChanged is
// object-level and moves on ANY attribute edit (a phone number update on a
// user with a years-old, stable sIDHistory bumps whenChanged exactly like a
// real sIDHistory injection would). The only AD-native source of a
// per-attribute change timestamp is replication metadata
// (msDS-ReplAttributeMetaData / `repadmin /showobjmeta`), a distinct,
// heavier collection mechanism this detector does not implement - this is a
// genuine AD limitation, not a bug fixable by tweaking this file. What this
// detector actually measures is therefore "recently modified object that
// also happens to carry sIDHistory," not "recent sIDHistory change" -
// title/description below say that honestly instead of implying attribute-
// level precision the code cannot provide.
//
// Coverage limitation: users only. Computer objects are not evaluated -
// parseComputer does not decode sIDHistory for computers at all, so a
// migrated computer account with injected sIDHistory is invisible to this
// detector today.
func (d *SIDHistoryRecentDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	threshold := now.AddDate(0, 0, -90) // 90 days ago - product heuristic, not tied to any cited standard

	var affected []types.User
	for _, user := range data.Users {
		if len(user.SIDHistory) == 0 {
			continue
		}

		// Use WhenChanged as a proxy for SIDHistory modification time.
		// If the user object was recently modified and has SIDHistory, flag it.
		if !user.WhenChanged.IsZero() && user.WhenChanged.After(threshold) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Recently Modified User Accounts Carrying SIDHistory",
		Description: "User accounts that carry a non-empty sIDHistory and were modified within the last 90 days. Active Directory does not expose a per-attribute last-modified timestamp for sIDHistory over LDAP, so whenChanged - which reflects ANY attribute change on the object, not specifically sIDHistory - is used as a proxy: a stable, long-migrated account that receives an unrelated edit (e.g. a phone number update) will also match. Computer objects are not evaluated by this detector.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSIDHistoryRecentDetector())
}
