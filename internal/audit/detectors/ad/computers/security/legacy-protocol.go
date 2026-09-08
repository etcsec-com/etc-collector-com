package security

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LegacyProtocolDetector detects computers using legacy protocols
type LegacyProtocolDetector struct {
	audit.BaseDetector
}

// NewLegacyProtocolDetector creates a new detector
func NewLegacyProtocolDetector() *LegacyProtocolDetector {
	return &LegacyProtocolDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_LEGACY_PROTOCOL", audit.CategoryComputers),
	}
}

var legacyOSPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Windows XP`),
	regexp.MustCompile(`(?i)Windows 2000`),
	regexp.MustCompile(`(?i)Windows NT`),
	regexp.MustCompile(`(?i)Server 2003`),
	regexp.MustCompile(`(?i)Windows Vista`),
}

// Detect executes the detection.
//
// This detector does not observe SMB dialect or NTLM version on the
// wire; it never did. The old Description and its static
// `"protocols": []string{"SMBv1","NTLMv1","DES","RC4"}` implied those four
// protocols were directly detected per computer, which is false - only two
// signals are actually measured: (1) an end-of-life OS version, correlated
// with SMBv1 (Microsoft Learn, "SMBv1 not installed by default in Windows
// Server and Windows" - learn.microsoft.com/en-us/windows-server/storage/
// file-server/troubleshoot/smbv1-not-installed-by-default-in-windows: SMBv1
// was only removed from the default install starting Windows 10 1709 /
// Windows Server 2019, so anything older shipped with it available), and
// (2) msDS-SupportedEncryptionTypes lacking AES (a directly-read AD
// attribute, not inferred). Details below is now honest about which of the
// two fired for each computer instead of claiming a blanket protocol list.
func (d *LegacyProtocolDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer
	legacyOSCount, weakEncryptionCount := 0, 0

	for _, c := range data.Computers {
		if !c.Enabled() {
			continue
		}

		hasLegacyOS := false
		for _, pattern := range legacyOSPatterns {
			if pattern.MatchString(c.OperatingSystem) {
				hasLegacyOS = true
				break
			}
		}
		if hasLegacyOS {
			affected = append(affected, c)
			legacyOSCount++
			continue
		}

		// Check supported encryption types (if only DES/RC4)
		if c.SupportedEncryptionTypes > 0 {
			// No AES128 (0x8) or AES256 (0x10)
			onlyLegacy := (c.SupportedEncryptionTypes & 0x18) == 0
			if onlyLegacy {
				affected = append(affected, c)
				weakEncryptionCount++
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Legacy Operating System or Weak Kerberos Encryption",
		Description: "Computer runs an end-of-life Windows version that predates Microsoft disabling SMBv1 by default, or has no AES Kerberos encryption type enabled (DES/RC4 only, crackable offline). SMB dialect and NTLM version are not directly observed by this detector.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}
	if len(affected) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation":         "Upgrade end-of-life systems. Enable AES encryption support (msDS-SupportedEncryptionTypes) on any account still limited to DES/RC4.",
			"legacyOSCount":          legacyOSCount,
			"weakKerberosEncryption": weakEncryptionCount,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLegacyProtocolDetector())
}
