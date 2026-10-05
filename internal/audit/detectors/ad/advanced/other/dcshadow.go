package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DCShadowDetector detects evidence of DCShadow attacks
type DCShadowDetector struct {
	audit.BaseDetector
}

// NewDCShadowDetector creates a new detector
func NewDCShadowDetector() *DCShadowDetector {
	return &DCShadowDetector{
		BaseDetector: audit.NewBaseDetector("DCSHADOW_EVIDENCE", audit.CategoryAdvanced),
	}
}

// uacServerTrustAccountFlag is the UAC flag for SERVER_TRUST_ACCOUNT (domain controller)
const uacServerTrustAccountFlag = 0x2000

// Detect executes the detection.
//
// Scope: this flags computer objects that carry the SERVER_TRUST_ACCOUNT UAC
// flag (or are already known domain controllers) whose distinguished name
// falls outside the standard "OU=Domain Controllers" container. That is a
// directory-hygiene / object-placement anomaly consistent with, but not
// proof of, a DCShadow registration.
//
// MITRE ATT&CK T1207 "Rogue Domain Controller" (attack.mitre.org/techniques/T1207/)
// and its associated detection strategy DET0276 (attack.mitre.org/detectionstrategies/DET0276/)
// document DCShadow evidence as the correlation of FOUR signals: (1)
// creation/modification of nTDSDSA and server objects under
// CN=Configuration,CN=Sites; (2) registration/use of the Directory
// Replication Service SPN (GC/ or the DRSUAPI interface GUID
// E3514235-4B06-11D1-AB04-00C04FC2DCD2); (3) replication RPC calls
// (DrsAddEntry, DrsReplicaAdd, GetNCChanges) originating from non-DC hosts;
// and (4) Kerberos authentication by non-DC machines using DRS-related SPNs.
//
// This detector implements NONE of those four signals directly - it has no
// coverage for nTDSDSA/server object churn, the DRS SPN, replication RPC
// calls, or Kerberos telemetry, all of which require live network/event
// data this collector (a point-in-time LDAP snapshot) does not gather. It
// only checks DC-OU placement, which is a narrower, indirect proxy. A hit
// here should be treated as a directory anomaly worth investigating
// (including benign causes, e.g. an OU restructure or migration tooling),
// not as confirmed forensic evidence of a DCShadow attack.
func (d *DCShadowDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	// Check DomainControllers for any DC outside the standard Domain Controllers OU
	for _, dc := range data.DomainControllers {
		if !isInDomainControllersOU(dc.DistinguishedName) && !isInDomainControllersOU(dc.DN) {
			affected = append(affected, dc)
		}
	}

	// Also check Computers for SERVER_TRUST_ACCOUNT outside Domain Controllers OU
	seen := make(map[string]bool)
	for _, dc := range affected {
		if dc.DN != "" {
			seen[dc.DN] = true
		}
		if dc.DistinguishedName != "" {
			seen[dc.DistinguishedName] = true
		}
	}

	for _, computer := range data.Computers {
		if (computer.UserAccountControl & uacServerTrustAccountFlag) == 0 {
			continue
		}

		dn := computer.DistinguishedName
		if dn == "" {
			dn = computer.DN
		}

		if seen[dn] {
			continue
		}

		if !isInDomainControllersOU(dn) {
			affected = append(affected, computer)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Domain Controller Object Outside Standard OU",
		Description: "A computer object with the SERVER_TRUST_ACCOUNT flag (or an already-known domain controller) was found outside the standard OU=Domain Controllers container. This is ONE of several evidence classes MITRE ATT&CK T1207 associates with a DCShadow rogue-DC registration (object placement), not the full set - this detector does not inspect nTDSDSA/server object churn, the DRS replication SPN, replication RPC calls, or Kerberos telemetry, which are the other signals MITRE documents for this technique. Treat a hit as a directory anomaly to investigate, not as confirmed evidence of an attack.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

// isInDomainControllersOU checks if the DN contains the standard Domain Controllers OU
func isInDomainControllersOU(dn string) bool {
	return strings.Contains(strings.ToLower(dn), "ou=domain controllers")
}

func init() {
	audit.MustRegister(NewDCShadowDetector())
}
