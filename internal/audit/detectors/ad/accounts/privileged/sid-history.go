package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SidHistoryDetector detects SID history attribute
type SidHistoryDetector struct {
	audit.BaseDetector
}

// NewSidHistoryDetector creates a new detector
func NewSidHistoryDetector() *SidHistoryDetector {
	return &SidHistoryDetector{
		BaseDetector: audit.NewBaseDetector("SID_HISTORY", audit.CategoryAccounts),
	}
}

// Detect executes the detection.
//
// sIDHistory (Microsoft Learn, "SID-History attribute", Win32 AD Schema
// reference; [MS-ADA3]) carries an object's SIDs from prior domains,
// normally populated only by inter-domain migration tooling (e.g. ADMT).
// A non-empty value outside a genuine migration is the classic
// sIDHistory-injection privilege escalation vector (MITRE ATT&CK
// T1134.005): forging a privileged domain's SID into this attribute grants
// the resulting access without any group membership change. The
// code<-field<-record chain is straightforward and correct - this status
// note is about verification, not a code defect: this path has never been
// observed firing on the lab, and no plant/revert has established it
// (there is no cross-domain migration history to produce a legitimate
// value, nor a forged one). Honestly "not observed", not "verified".
func (d *SidHistoryDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if len(u.SIDHistory) > 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "SID History Present",
		Description: "User accounts with sIDHistory attribute. Can be abused for privilege escalation.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSidHistoryDetector())
}
