package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Shared test helpers for the R12.1/R12.2 sub-recommendation detector tests
// (anssi-r12-1-force-pwd-reset-privs_test.go,
// anssi-r12-2-user-restrictions-privs_test.go).
//
// ANSSI_R12_2 emitted 1130 HIGH findings on DC01 with zero
// affectedEntities, every one of them the READ_PROP ACE that AD itself places
// on each user object at domain install (qa verdict §3). R12.1 carries the same
// code defect. Those tests pin both the false positive and the true positive.

const (
	r12DomainDN = "DC=example,DC=com"
	r12TargetDN = "CN=Akira Jackson,OU=IT," + r12DomainDN

	sidPreWin2000 = "S-1-5-32-554" // BUILTIN\Pre-Windows 2000 Compatible Access
	sidHelpdesk   = "S-1-5-21-1234567890-1111111111-2222222222-1337"

	maskReadProp = 0x00000010
)

func r12Data(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			r12TargetDN: {DN: r12TargetDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
		},
	}
}

func r12Detect(t *testing.T, d audit.Detector, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("%s: expected exactly 1 finding, got %d", d.ID(), len(findings))
	}
	return findings[0]
}
