package network

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestDcDiskSpaceLow_NotRegistered documents the RETIRER decision:
// DC_DISK_SPACE_LOW was an unimplemented stub (Count hardcoded to 0, "Would
// be populated with actual disk space checks"). No provider in this repo
// collects DC disk space - there is no WMI/CIM channel - so the condition
// is not measurable with data actually collected today. A detector that
// can only guess must not be registered.
func TestDcDiskSpaceLow_NotRegistered(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("DC_DISK_SPACE_LOW"); ok {
		t.Fatal("DC_DISK_SPACE_LOW must not be registered: no provider collects DC disk space, " +
			"so this detector can only ever guess (Count hardcoded to 0) - a guessing detector " +
			"is worse than no control at all")
	}
}
