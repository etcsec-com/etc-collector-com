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

// Coverage limitation: users only. Computer objects are not evaluated -
// parseComputer does not decode sIDHistory for computers, so a migrated
// computer account with an injected privileged SID is invisible here.
func (d *SIDHistoryWellKnownDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Well-known privileged RID/SID suffixes that should never appear in
	// SIDHistory. Domain-relative RIDs per Microsoft Learn, "Well-known
	// SIDs" (learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
	// and MS-DTYP §2.4.2.4; -498/-516/-518/-519/-521/-512/-502/-500 are the
	// domain SID's own well-known RIDs. -544 (BUILTIN\Administrators, listed
	// on the same Microsoft reference as S-1-5-32-544) was missing: it is a
	// documented target of SID-History injection privilege escalation
	// (inject the domain SID + "-544" style suffix, or the local BUILTIN
	// SID directly, into a low-privileged account's sIDHistory to gain
	// local admin on every machine that resolves BUILTIN\Administrators the
	// same way) - the same attack class this list already covers for
	// Domain/Enterprise Admins. Widens the match set; not confirmed against
	// live lab volume this session (sIDHistory cannot be safely planted in
	// this environment - see file-level constraints).
	privilegedRIDs := []string{
		"-500", // Administrator
		"-502", // krbtgt
		"-512", // Domain Admins
		"-516", // Domain Controllers
		"-518", // Schema Admins
		"-519", // Enterprise Admins
		"-498", // Enterprise Read-Only Domain Controllers
		"-521", // Read-Only Domain Controllers
		"-544", // BUILTIN\Administrators (S-1-5-32-544)
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
