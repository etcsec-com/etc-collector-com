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

// Detect executes the detection
func (d *LegacyProtocolDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Enabled() {
			continue
		}

		// Legacy OS definitely uses legacy protocols
		hasLegacyOS := false
		for _, pattern := range legacyOSPatterns {
			if pattern.MatchString(c.OperatingSystem) {
				hasLegacyOS = true
				break
			}
		}
		if hasLegacyOS {
			affected = append(affected, c)
			continue
		}

		// Check supported encryption types (if only DES/RC4)
		if c.SupportedEncryptionTypes > 0 {
			// No AES128 (0x8) or AES256 (0x10)
			onlyLegacy := (c.SupportedEncryptionTypes & 0x18) == 0
			if onlyLegacy {
				affected = append(affected, c)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Legacy Protocol Support",
		Description: "Computers configured to use legacy protocols (SMBv1, NTLMv1, DES/RC4 only). These are vulnerable to relay attacks, credential theft, and encryption downgrade.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}
	if len(affected) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Upgrade legacy systems or disable legacy protocols. Enable AES encryption support.",
			"protocols":      []string{"SMBv1", "NTLMv1", "DES", "RC4"},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLegacyProtocolDetector())
}
