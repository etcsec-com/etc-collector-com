package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoSessionControlsDetector checks if any CA policy uses session controls
type NoSessionControlsDetector struct {
	audit.BaseDetector
}

// NewNoSessionControlsDetector creates a new detector
func NewNoSessionControlsDetector() *NoSessionControlsDetector {
	return &NoSessionControlsDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_SESSION_CONTROLS", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
//
// Known limitation (non vu, not fixable in this detector alone): Microsoft
// Graph's signInFrequencySessionControl carries an isEnabled flag and a
// frequencyInterval of "timeBased" or "everyTime" (Microsoft Learn,
// "signInFrequencySessionControl resource type", learn.microsoft.com/en-us/
// graph/api/resources/signinfrequencysessioncontrol) - for "everyTime"
// policies (recommended by Microsoft for risk-based re-auth), value/type are
// not meaningful the way they are for "timeBased". internal/providers/azure/
// client.go's convertConditionalAccessPolicy only reads GetValue() and
// GetTypeEscaped(), never GetIsEnabled() or GetFrequencyInterval(). A policy
// using "Sign-in frequency: Every time" can read as SignInFrequencyValue==0
// here, making this check wrongly report "no session controls" even though
// one is configured. Fixing this needs new fields on
// types.ConditionalAccessPolicy and a collector change, both out of this
// detector's scope.
func (d *NoSessionControlsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasSessionControls := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State != "enabled" {
			continue
		}

		if p.SignInFrequencyValue > 0 || p.PersistentBrowserMode != "" {
			hasSessionControls = true
			break
		}
	}

	count := 0
	if !hasSessionControls {
		count = 1
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "No CA Policy with Session Controls",
		Description: "No CA policy configures session controls (sign-in frequency, persistent browser). " +
			"A sign-in frequency of 'Every time' is not currently detected (collector does not capture " +
			"frequencyInterval on Conditional Access policies) and may read as no session control here.",
		Count: count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoSessionControlsDetector())
}
