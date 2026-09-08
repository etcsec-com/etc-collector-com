package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R2PrivilegedAccountsDetector checks Domain Admins hygiene: group size
// against a product benchmark, and absence of service accounts in the
// group.
//
// Source check (PA-099 v1.0, 02/10/2023 - full text searched for "10 comptes",
// "moins de 10", "nombre" + "administrateurs"): R1 (adopt a tiered privileged
// access model), R2 (protect each tier proportionately) and R8 (segregate
// administration per tier) all bear on Domain Admins hygiene in general
// terms, but NONE of them - nor any other PA-099 recommendation - specifies
// a numeric ceiling on Domain Admins membership. The "< 10" figure below is
// an etc-collector product benchmark, not an ANSSI-mandated threshold; it
// must not be presented as one.
type R2PrivilegedAccountsDetector struct {
	audit.BaseDetector
}

// NewR2PrivilegedAccountsDetector creates a new detector
func NewR2PrivilegedAccountsDetector() *R2PrivilegedAccountsDetector {
	return &R2PrivilegedAccountsDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R2_PRIVILEGED_ACCOUNTS", audit.CategoryCompliance),
	}
}

// daCountBenchmark is an etc-collector product benchmark for Domain Admins
// group size, not a number PA-099 specifies (see type doc above).
const daCountBenchmark = 10

// Detect executes the detection
func (d *R2PrivilegedAccountsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	// Count domain admins
	daCount := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		for _, memberOf := range u.MemberOf {
			if strings.Contains(strings.ToLower(memberOf), "domain admins") {
				daCount++
				break
			}
		}
	}

	if daCount > daCountBenchmark {
		issues = append(issues, fmt.Sprintf("More than %d Domain Admin accounts (product benchmark, not an ANSSI-mandated threshold)", daCountBenchmark))
	}

	// Check for service accounts in DA
	for _, u := range data.Users {
		if len(u.ServicePrincipalNames) > 0 {
			for _, memberOf := range u.MemberOf {
				if strings.Contains(strings.ToLower(memberOf), "domain admins") {
					issues = append(issues, "Service account in Domain Admins group")
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Domain Admins Hygiene Non-Compliant",
		Description: fmt.Sprintf("Privileged account management does not follow the tier-segregation principle behind ANSSI PA-099 R1/R2/R8: service accounts must not sit in Domain Admins. The >%d Domain Admins headcount check is a separate, etc-collector product benchmark - PA-099 specifies no numeric ceiling on Domain Admins membership.", daCountBenchmark),
		Count:       0,
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations":   issues,
			"framework":    "ANSSI",
			"control":      "R1/R2/R8",
			"domainAdmins": daCount,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewR2PrivilegedAccountsDetector())
}
