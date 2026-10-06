package serviceaccounts

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestNaming_HyphenPrefixFlagged pins the fix: Microsoft's own documented
// convention ("Secure user-based service accounts in Active Directory",
// Microsoft Learn) is the hyphenated "svc-" prefix, exemplified as
// "svc-HRDataConnector". The old pattern set only matched the underscore
// form ("svc_") and missed this one.
func TestNaming_HyphenPrefixFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "svc-HRDataConnector"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: \"svc-HRDataConnector\" matches Microsoft's documented naming convention", findings[0].Count)
	}
}

// TestNaming_DotVariantFlagged pins the dotted-prefix gap seen on the lab
// (svc.* accounts).
func TestNaming_DotVariantFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "svc.backup"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: \"svc.backup\" is a naming variant this detector must catch", findings[0].Count)
	}
}

// TestNaming_UnrelatedAccountNotFlagged guards against over-matching.
func TestNaming_UnrelatedAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "jdupont"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an ordinary username must not match", findings[0].Count)
	}
}

// TestNaming_DisabledAccountNotFlagged pins the Disabled guard: a disabled
// account matching a naming pattern must not be reported here - that case
// belongs to the _ON_DISABLED_ACCOUNT variant, not this detector.
func TestNaming_DisabledAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "svc_disabledmutationcheck", Disabled: true},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled account matching a naming pattern must not be flagged", findings[0].Count)
	}
}

// TestNaming_SPNAccountNotFlagged pins the SPN exclusion: an active account
// matching a naming pattern but carrying a SPN is covered by
// SERVICE_ACCOUNT_WITH_SPN instead, not here.
func TestNaming_SPNAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{
				SAMAccountName:        "svc_spnmutationcheck",
				ServicePrincipalNames: []string{"HTTP/spnmutationcheck.example.org"},
			},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an account with a SPN must not be flagged (covered by SERVICE_ACCOUNT_WITH_SPN)", findings[0].Count)
	}
}
