package organization

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WrongOuDetector checks for computers in default Computers container
type WrongOuDetector struct {
	audit.BaseDetector
}

// NewWrongOuDetector creates a new detector
func NewWrongOuDetector() *WrongOuDetector {
	return &WrongOuDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_WRONG_OU", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *WrongOuDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
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
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Computer in Default Container",
		Description: "Computer in default Computers container instead of an organizational OU. May not receive proper Group Policy and indicates lack of organization.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWrongOuDetector())
}
