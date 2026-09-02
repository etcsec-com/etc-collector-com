package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R3StrongAuthDetector checks ANSSI R3 strong authentication compliance
type R3StrongAuthDetector struct {
	audit.BaseDetector
}

// NewR3StrongAuthDetector creates a new detector
func NewR3StrongAuthDetector() *R3StrongAuthDetector {
	return &R3StrongAuthDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R3_STRONG_AUTH", audit.CategoryCompliance),
	}
}

// UAC flag for smartcard required
const uacSmartcardRequired = 0x40000

// Detect executes the detection
func (d *R3StrongAuthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Check if privileged accounts require smartcard. T_129 — this used to
	// be a bare counter with Count hardwired to 0/1 (motif(c): no
	// AffectedEntities ever, "inactionnable pour le client") and a dead
	// protectedUsersCount computation (comment admitted "would need actual
	// group name comparison" — computed, never read). The affected admins
	// are now collected so they can be reported; Count stays binary (0/1),
	// matching this detector's existing semantics.
	var adminsWithoutSmartcard []types.User
	for _, u := range data.Users {
		if !u.Enabled() || !u.AdminCount {
			continue
		}
		smartcardRequired := (u.UserAccountControl & uacSmartcardRequired) != 0
		if !smartcardRequired {
			adminsWithoutSmartcard = append(adminsWithoutSmartcard, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ANSSI R3 - Strong Authentication Non-Compliant",
		Description: "Strong authentication not enforced per ANSSI R3. Privileged accounts should require smartcard authentication.",
		Count:       0,
	}

	if len(adminsWithoutSmartcard) > 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations":             []string{"Privileged accounts without smartcard requirement"},
			"framework":              "ANSSI",
			"control":                "R3",
			"adminsWithoutSmartcard": len(adminsWithoutSmartcard),
		}
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities(adminsWithoutSmartcard)
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewR3StrongAuthDetector())
}
