package organization

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WrongOuOnDisabledAccountDetector checks for disabled computer accounts
// directly in the default Computers container. Split out of
// WrongOuDetector: a disabled computer does not authenticate, so it never
// applies Group Policy regardless of which container holds it - the live
// policy-application gap the active detector flags does not apply to it.
// The misplacement is still worth tracking as organizational residue, at
// Info (one rung below the active detector's Low, since there is no live
// policy gap left once the account is disabled): it would matter again as
// a live concern if the account is re-enabled without being relocated
// first.
//
// Named COMPUTER_WRONG_OU_ON_DISABLED_ACCOUNT, not COMPUTER_WRONG_OU_DISABLED:
// the _DISABLED suffix is reserved elsewhere in this catalog for "a
// protection was turned off" (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED,
// ...), which reads as bad news. Naming the population instead of a
// mechanism state avoids an auditor misreading this as the risk itself
// being off.
type WrongOuOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewWrongOuOnDisabledAccountDetector creates a new detector
func NewWrongOuOnDisabledAccountDetector() *WrongOuOnDisabledAccountDetector {
	return &WrongOuOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_WRONG_OU_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *WrongOuOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}

		// Check if computer is directly in the default Computers container
		// DN format: CN=COMPUTER$,CN=Computers,DC=domain,DC=com
		dnLower := strings.ToLower(c.DN)

		// Check if it's in CN=Computers (not OU=)
		// This catches: CN=PC01$,CN=Computers,DC=example,DC=com
		isInDefaultContainer := strings.Contains(dnLower, ",cn=computers,dc=")

		if isInDefaultContainer {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Computer in Default Container - Disabled Accounts",
		Description: "Disabled computer account in the default Computers container instead of an organizational OU. Group Policy no longer applies while the account is disabled, so this is organizational residue rather than a live policy gap - but it would resurface as a live concern if the account is re-enabled without being relocated first.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWrongOuOnDisabledAccountDetector())
}
