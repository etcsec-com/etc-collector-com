package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC11Detector detects ESC11: IF_ENFORCEENCRYPTICERTREQUEST Not Enforced
type ESC11Detector struct {
	audit.BaseDetector
}

// NewESC11Detector creates a new detector
func NewESC11Detector() *ESC11Detector {
	return &ESC11Detector{
		BaseDetector: audit.NewBaseDetector("ESC11_ICERT_REQUEST_ENFORCEMENT", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC11Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// IF_ENFORCEENCRYPTICERTREQUEST lives in the CA's local registry at
	// HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\InterfaceFlags
	// (bit 0x00000200). Per Microsoft Learn, Defender for Identity - "Enforce encryption
	// for RPC certificate enrollment interface (ESC11)"
	// (learn.microsoft.com/defender-for-identity/security-assessment-enforce-encryption-rpc):
	// "The IF_ENFORCEENCRYPTICERTREQUEST flag is on by default, but is often turned off to
	// allow clients that can't support the required RPC authentication level" - and that
	// same article notes its own assessment "is available only to customers who have
	// installed a sensor on an AD CS server", i.e. even Microsoft's own tooling needs local
	// access to the CA to read this value. It has no LDAP-readable counterpart, so a
	// directory-only collector structurally cannot observe it, and - being on by default -
	// its mere absence from LDAP data says nothing about whether the environment is
	// actually vulnerable.
	//
	// This finding is therefore a product signal (a manual-verification pointer), not a
	// compliance/vulnerability determination - Count reflects "AD CS is deployed, go check
	// the CA(s)", not a detected weakness.
	count := 0
	if len(data.CertTemplates) > 0 {
		count = 1 // AD CS is in scope; surfaced as a manual-check reminder.
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "ESC11 - RPC Encryption Enforcement (Manual Verification Required)",
		Description: "Not an automated finding: RPC encryption enforcement for certificate enrollment (IF_ENFORCEENCRYPTICERTREQUEST) is a per-CA registry flag that cannot be read via LDAP, and it is enabled by default on Windows CAs. This entry is a reminder to verify it manually - it does not confirm a vulnerability.",
		Count:       count,
		Details: map[string]interface{}{
			"note":           "Check InterfaceFlags registry key on CA servers. Flag 0x00000200 (IF_ENFORCEENCRYPTICERTREQUEST) is on by default; confirm it hasn't been turned off for legacy client compatibility.",
			"registryPath":   "HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CA>\\InterfaceFlags",
			"recommendation": "Set IF_ENFORCEENCRYPTICERTREQUEST flag using: certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC11Detector())
}
