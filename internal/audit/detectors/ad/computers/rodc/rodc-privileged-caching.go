package rodc

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RODCPrivilegedCachingDetector flags Read-Only Domain Controllers whose revealed
// credential list includes members of privileged groups (Domain Admins, Enterprise
// Admins, etc.). Matches Purple Knight SI000022.
type RODCPrivilegedCachingDetector struct {
	audit.BaseDetector
}

func NewRODCPrivilegedCachingDetector() *RODCPrivilegedCachingDetector {
	return &RODCPrivilegedCachingDetector{
		BaseDetector: audit.NewBaseDetector("RODC_PRIVILEGED_CACHING", audit.CategoryComputers),
	}
}

func (d *RODCPrivilegedCachingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build a set of DNs (lowercased) for privileged principals: users with
	// adminCount, groups with adminCount, and well-known privileged groups/users
	// identified via SID suffix.
	privilegedDNs := make(map[string]string) // DN → display name
	for i := range data.Users {
		u := &data.Users[i]
		if u.AdminCount || audit.IsPrivilegedSID(u.ObjectSID) {
			if u.DN != "" {
				privilegedDNs[strings.ToLower(u.DN)] = u.SAMAccountName
			}
		}
	}
	for i := range data.Groups {
		g := &data.Groups[i]
		if g.AdminCount || audit.IsPrivilegedSID(g.ObjectSID) {
			if g.DN != "" {
				privilegedDNs[strings.ToLower(g.DN)] = g.SAMAccountName
			}
		}
	}

	var affected []types.Computer
	pairs := make([]string, 0)

	for i := range data.Computers {
		c := &data.Computers[i]
		if !c.IsRODC {
			continue
		}
		flaggedThisRODC := false
		for _, revealedDN := range c.RevealedList {
			key := strings.ToLower(revealedDN)
			if name, isPriv := privilegedDNs[key]; isPriv {
				if !flaggedThisRODC {
					affected = append(affected, *c)
					flaggedThisRODC = true
				}
				host := c.DNSHostName
				if host == "" {
					host = c.SAMAccountName
				}
				display := name
				if display == "" {
					display = revealedDN
				}
				pairs = append(pairs, fmt.Sprintf("%s cached credential for %s", host, display))
			}
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityCritical,
		Category: string(d.Category()),
		Title:    "RODC caches credentials for privileged principals",
		Description: "One or more Read-Only Domain Controllers have revealed (cached) credentials " +
			"for principals in privileged groups. A compromise of the RODC would expose these " +
			"credentials even though RODCs are designed to hold only non-sensitive passwords.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Review msDS-RevealedList on each RODC. Add privileged principals to msDS-NeverRevealGroup (or the Denied RODC Password Replication Group).",
			"pairs":          pairs,
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRODCPrivilegedCachingDetector())
}
