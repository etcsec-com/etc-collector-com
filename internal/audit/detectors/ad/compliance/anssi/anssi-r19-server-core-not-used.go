package anssi

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-PA-099 R19+ - Server Core usage on Tier 0 DCs cannot be confirmed
// via LDAP.
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf
//
// The previous implementation flagged any DC whose LDAP operatingSystem
// string didn't contain "server core" or "(core)" as a full-GUI (non-
// compliant) install. That premise is false: Microsoft's operatingSystem
// attribute reports the same string ("Windows Server 2019 Standard", etc.)
// for a Server Core install and a Desktop Experience install of the same
// edition - there is no LDAP attribute that distinguishes them (confirmed:
// the code's own prior comment already said "Microsoft does not provide a
// dedicated LDAP attribute", but the implementation still treated the
// absence of a substring that real DCs never carry as proof of
// non-compliance). A substring match against operatingSystem can therefore
// never observe a true "compliant" state - every DC, Server Core or not,
// fails the same way, which made the check structurally unable to confirm
// anything and turned every domain's R19+ finding into a guaranteed false
// positive. The only reliable source is the registry InstallationType value
// on each DC (HKLM\Software\Microsoft\Windows NT\CurrentVersion\
// InstallationType = "Server Core"), which is not collected over LDAP.
// Until that's collected, this detector reports the gap honestly instead of
// a fabricated verdict.

type R19ServerCoreNotUsedDetector struct{ audit.BaseDetector }

func NewR19ServerCoreNotUsedDetector() *R19ServerCoreNotUsedDetector {
	return &R19ServerCoreNotUsedDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R19_SERVER_CORE_NOT_USED", audit.CategoryCompliance),
	}
}

func (d *R19ServerCoreNotUsedDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	dcs := data.DomainControllers
	if len(dcs) == 0 {
		return nil
	}

	return wrapFindingWithRepro(d, "ANSSI R19+ - Server Core usage cannot be confirmed via LDAP",
		fmt.Sprintf("ANSSI R19+ (p.35) recommends Windows Server Core on the Tier 0 perimeter to reduce attack surface. This cannot be verified through LDAP: the operatingSystem attribute reports the same string for a Server Core install and a Desktop Experience install of the same Windows Server edition, so no LDAP-only check can confirm or deny R19+ compliance. %d Domain Controller(s) in this domain - confirm directly on each host via the registry (HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\InstallationType = 'Server Core').", len(dcs)),
		types.SeverityInfo, len(dcs), computersToEntities(dcs, data.IncludeDetails),
		&types.FindingReproducibility{
			LDAPFilter: "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
			LDAPAttrs:  []string{"sAMAccountName", "operatingSystem"},
			Notes:      "LDAP's operatingSystem does not vary by install type and cannot confirm Server Core usage. Cross-check the InstallationType registry value on each DC instead.",
		})
}

func init() {
	audit.MustRegister(NewR19ServerCoreNotUsedDetector())
}
