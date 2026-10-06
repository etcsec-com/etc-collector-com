package ldap

import (
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestFilterDisplaySpecifierChanges_LeafCodeAttributeFires is the RED->GREEN
// case for a regression: before the fix, DISPLAY_SPECIFIER_CHANGES probed the locale
// CONTAINER DN (e.g. CN=409,CN=DisplaySpecifiers,...) rather than the leaf
// object actually holding adminContextMenu - msDS-ReplAttributeMetaData is
// built per object (MS-ADTS), so a change on the leaf never appears in the
// container's own metadata. filterDisplaySpecifierChanges operates on leaf
// DNs directly.
func TestFilterDisplaySpecifierChanges_LeafCodeAttributeFires(t *testing.T) {
	leafDN := "CN=user-Display,CN=409,CN=DisplaySpecifiers,CN=Configuration,DC=example,DC=com"
	cutoff := time.Now().AddDate(0, 0, -90)
	recent := time.Now().AddDate(0, 0, -1)

	metaByDN := map[string][]audit.ReplMetadataEntry{
		leafDN: {{AttributeName: "adminContextMenu", LastChangeTime: recent}},
	}

	changed := filterDisplaySpecifierChanges([]string{leafDN}, metaByDN, cutoff)
	if len(changed) != 1 || changed[0] != leafDN {
		t.Fatalf("a recent adminContextMenu change on the leaf must fire, got %v", changed)
	}
}

// TestFilterDisplaySpecifierChanges_NonCodeAttributeDoesNotFire covers the
// missing-attribute-filter half of the same bug: without it, ANY attribute
// change (including a container's own creation timestamp on a domain younger
// than 90 days) would have flagged every locale.
func TestFilterDisplaySpecifierChanges_NonCodeAttributeDoesNotFire(t *testing.T) {
	leafDN := "CN=user-Display,CN=409,CN=DisplaySpecifiers,CN=Configuration,DC=example,DC=com"
	cutoff := time.Now().AddDate(0, 0, -90)
	recent := time.Now().AddDate(0, 0, -1)

	metaByDN := map[string][]audit.ReplMetadataEntry{
		// whenCreated / an unrelated attribute - not one of the 5 code-bearing ones.
		leafDN: {{AttributeName: "description", LastChangeTime: recent}},
	}

	changed := filterDisplaySpecifierChanges([]string{leafDN}, metaByDN, cutoff)
	if len(changed) != 0 {
		t.Fatalf("a non-code attribute change must not fire, got %v", changed)
	}
}

// TestFilterDisplaySpecifierChanges_OldChangeDoesNotFire guards the 90-day window.
func TestFilterDisplaySpecifierChanges_OldChangeDoesNotFire(t *testing.T) {
	leafDN := "CN=group-Display,CN=409,CN=DisplaySpecifiers,CN=Configuration,DC=example,DC=com"
	cutoff := time.Now().AddDate(0, 0, -90)
	old := time.Now().AddDate(0, 0, -200)

	metaByDN := map[string][]audit.ReplMetadataEntry{
		leafDN: {{AttributeName: "contextMenu", LastChangeTime: old}},
	}

	changed := filterDisplaySpecifierChanges([]string{leafDN}, metaByDN, cutoff)
	if len(changed) != 0 {
		t.Fatalf("a change older than the cutoff must not fire, got %v", changed)
	}
}

// TestIsDisplaySpecifierCodeAttribute covers all 5 code-bearing attributes,
// case-insensitively, and rejects an unrelated one.
func TestIsDisplaySpecifierCodeAttribute(t *testing.T) {
	for _, attr := range []string{
		"adminContextMenu", "ADMINCONTEXTMENU", "contextMenu",
		"creationWizard", "adminPropertyPages", "shellPropertyPages",
	} {
		if !isDisplaySpecifierCodeAttribute(attr) {
			t.Errorf("%q must be recognised as a code-bearing attribute", attr)
		}
	}
	if isDisplaySpecifierCodeAttribute("whenChanged") {
		t.Error("whenChanged is not a code-bearing attribute")
	}
}
