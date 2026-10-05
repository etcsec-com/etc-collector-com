package network

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestDcTimeSync_DetectorRetired documents the RETIRER decision:
// DC_TIME_SYNC_ISSUE flagged DCs by stale LastLogon (>7 days) on their
// machine account - a proxy for "offline/decommissioned DC", not for
// NTP/Kerberos clock skew, which the product never collects (no w32tm
// query, no LDAP time attribute). A DC with real clock drift that keeps
// authenticating was never caught, and a stale-but-in-sync DC was flagged
// wrongly. Retired: the condition the title/description promise is not
// measurable from any data this product collects today.
func TestDcTimeSync_DetectorRetired(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("DC_TIME_SYNC_ISSUE"); ok {
		t.Fatal("DC_TIME_SYNC_ISSUE must no longer be registered: LastLogon staleness is not a measurable clock-skew signal")
	}
}
