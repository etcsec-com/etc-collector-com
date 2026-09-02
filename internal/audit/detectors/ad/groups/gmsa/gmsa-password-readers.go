package gmsa

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GMSAPasswordReadersDetector enumerates non-privileged principals that can retrieve
// a gMSA managed password via the msDS-GroupMSAMembership security descriptor.
// Matches Purple Knight SI000083.
type GMSAPasswordReadersDetector struct {
	audit.BaseDetector
}

// NewGMSAPasswordReadersDetector creates a new detector.
func NewGMSAPasswordReadersDetector() *GMSAPasswordReadersDetector {
	return &GMSAPasswordReadersDetector{
		BaseDetector: audit.NewBaseDetector("GMSA_PASSWORD_READERS", audit.CategoryGroups),
	}
}

// Detect returns one finding listing every (gMSA, non-privileged reader) pair.
func (d *GMSAPasswordReadersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Index users by ObjectSID for fast privilege lookup of resolved readers.
	usersBySID := make(map[string]*types.User, len(data.Users))
	for i := range data.Users {
		if sid := data.Users[i].ObjectSID; sid != "" {
			usersBySID[sid] = &data.Users[i]
		}
	}
	groupsBySID := make(map[string]*types.Group, len(data.Groups))
	for i := range data.Groups {
		if sid := data.Groups[i].ObjectSID; sid != "" {
			groupsBySID[sid] = &data.Groups[i]
		}
	}

	var affected []types.User
	pairs := make([]string, 0)

	for i := range data.Users {
		u := &data.Users[i]
		if !u.IsGMSA || len(u.GMSAMembership) == 0 {
			continue
		}

		readers := audit.ParseRBCDTrustees(u.GMSAMembership)
		gmsaHasNonPriv := false
		for _, sid := range readers {
			if audit.IsPrivilegedSID(sid) {
				continue
			}
			// Skip if reader resolves to a user/group already flagged as privileged.
			if ru, ok := usersBySID[sid]; ok && ru.AdminCount {
				continue
			}
			if rg, ok := groupsBySID[sid]; ok && rg.AdminCount {
				continue
			}

			gmsaHasNonPriv = true
			readerName := sid
			if ru, ok := usersBySID[sid]; ok && ru.SAMAccountName != "" {
				readerName = ru.SAMAccountName
			} else if rg, ok := groupsBySID[sid]; ok && rg.SAMAccountName != "" {
				readerName = rg.SAMAccountName
			}
			gmsaName := u.SAMAccountName
			if gmsaName == "" {
				gmsaName = u.DN
			}
			pairs = append(pairs, fmt.Sprintf("%s can read password of %s", readerName, gmsaName))
		}
		if gmsaHasNonPriv {
			affected = append(affected, *u)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "Non-privileged principal can read gMSA password",
		Description: "One or more Group Managed Service Accounts (gMSA) allow non-privileged " +
			"principals to retrieve their managed password via msDS-GroupMSAMembership. Any reader " +
			"of the password can impersonate the service account.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Remove non-privileged principals from the gMSA PrincipalsAllowedToRetrieveManagedPassword set.",
			"pairs":          pairs,
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGMSAPasswordReadersDetector())
}
