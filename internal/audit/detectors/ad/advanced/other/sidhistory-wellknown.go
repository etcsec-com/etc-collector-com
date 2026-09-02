package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SIDHistoryWellKnownDetector checks for well-known privileged SIDs in sIDHistory
type SIDHistoryWellKnownDetector struct {
	audit.BaseDetector
}

func NewSIDHistoryWellKnownDetector() *SIDHistoryWellKnownDetector {
	return &SIDHistoryWellKnownDetector{
		BaseDetector: audit.NewBaseDetector("SIDHISTORY_WELLKNOWN_SIDS", audit.CategoryAdvanced),
	}
}

func (d *SIDHistoryWellKnownDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Well-known privileged RID suffixes that should never appear in SIDHistory
	privilegedRIDs := []string{
		"-500", // Administrator
		"-502", // krbtgt
		"-512", // Domain Admins
		"-516", // Domain Controllers
		"-518", // Schema Admins
		"-519", // Enterprise Admins
		"-498", // Enterprise Read-Only Domain Controllers
		"-521", // Read-Only Domain Controllers
	}

	var affected []types.User
	for _, user := range data.Users {
		if len(user.SIDHistory) == 0 {
			continue
		}
		for _, sid := range user.SIDHistory {
			for _, rid := range privilegedRIDs {
				if strings.HasSuffix(sid, rid) {
					affected = append(affected, user)
					goto nextUser
				}
			}
		}
	nextUser:
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Well-Known Privileged SIDs in SIDHistory",
		Description: "Users with SIDHistory containing well-known privileged SIDs (Domain Admins, Enterprise Admins, etc.). This grants them the privileges of those groups even if they are not members, enabling privilege escalation and persistence.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSIDHistoryWellKnownDetector())
}
