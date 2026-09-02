package kerberos

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberoastingRiskDetector flags user accounts that carry a Service
// Principal Name (Kerberoastable). v3.1.21 — splits findings by Tier 0
// membership so a Tier 0 admin with SPN is reported as Critical (one
// step from forest takeover) while ordinary service accounts are reported
// as High.
//
// B_011 / T_036 — this comment used to say "Medium severity" for the
// non-Tier 0 case while the code emitted High (:72). Doc drift only; the
// behaviour was verified correct on a live plant→diff and is unchanged.
//
// The overlap with SERVICE_ACCOUNT_WITH_SPN is deliberate and is NOT a
// duplication: that detector's population is a strict superset (every SPN
// account, whatever its privilege), and this one adds the priority signal
// "this SPN account is Tier 0". See detectors/ad/dedup.go, rule R3.
//
// The Tier 0 partitioning absorbs the logic of the deleted
// ANSSI_R69_TIER0_SPN_EXPOSED detector — recursive group expansion +
// AdminCount=1 (AdminSDHolder) + tier0_groups.yaml customer overrides
// via helpers.Tier0Members.
type KerberoastingRiskDetector struct {
	audit.BaseDetector
}

// NewKerberoastingRiskDetector creates a new detector
func NewKerberoastingRiskDetector() *KerberoastingRiskDetector {
	return &KerberoastingRiskDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROASTING_RISK", audit.CategoryKerberos),
	}
}

// Detect partitions Kerberoastable users by Tier 0 membership and emits
// one finding per non-empty partition. A Tier 0 admin with SPN produces
// a Critical finding (R69 scope); regular service accounts produce a
// Medium finding.
func (d *KerberoastingRiskDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	tier0 := helpers.Tier0Members(data, customTier0Groups(data))

	var tier0Affected, otherAffected []types.User
	for _, user := range data.Users {
		if user.Disabled || len(user.ServicePrincipalNames) == 0 {
			continue
		}
		if tier0[strings.ToLower(user.DN)] {
			tier0Affected = append(tier0Affected, user)
		} else {
			otherAffected = append(otherAffected, user)
		}
	}

	var out []types.Finding
	if len(tier0Affected) > 0 {
		f := types.Finding{
			Type:     d.ID(),
			Severity: types.SeverityCritical,
			Category: string(d.Category()),
			Title:    "Kerberoasting Risk — Tier 0 admin exposes a SPN",
			Description: fmt.Sprintf(
				"%d Tier 0 admin account(s) carry a SPN, exposing them to Kerberoasting (any authenticated user can request a TGS and crack the returned ticket offline). Tier 0 expansion includes recursive group nesting + AdminCount=1 + tier0_groups.yaml customer config. Move the SPN to a dedicated service identity (gMSA preferred) outside Tier 0, or remove the SPN if unused. ANSSI PA-099 R69 violation.",
				len(tier0Affected)),
			Count: len(tier0Affected),
		}
		if data.IncludeDetails {
			f.AffectedEntities = helpers.ToAffectedUserEntities(tier0Affected)
		}
		out = append(out, f)
	}
	if len(otherAffected) > 0 {
		f := types.Finding{
			Type:     d.ID(),
			Severity: types.SeverityHigh,
			Category: string(d.Category()),
			Title:    "Kerberoasting Risk — service accounts with SPN",
			Description: fmt.Sprintf(
				"%d non-Tier-0 user account(s) carry a SPN, exposing them to Kerberoasting attacks (offline cracking of TGS tickets). Use Group Managed Service Accounts (gMSA) where possible — gMSA passwords rotate automatically and are 240-byte random.",
				len(otherAffected)),
			Count: len(otherAffected),
		}
		if data.IncludeDetails {
			f.AffectedEntities = helpers.ToAffectedUserEntities(otherAffected)
		}
		out = append(out, f)
	}
	return out
}

// customTier0Groups returns the customer-supplied Tier 0 group DNs from
// data.Tier0Config (loaded from tier0_groups.yaml). Returns nil when no
// config is loaded — helpers.Tier0Members then falls back to its
// hardcoded default list (12 well-known privileged groups).
func customTier0Groups(data *audit.DetectorData) []string {
	if data == nil || data.Tier0Config == nil {
		return nil
	}
	return data.Tier0Config.Groups
}

func init() {
	audit.MustRegister(NewKerberoastingRiskDetector())
}
