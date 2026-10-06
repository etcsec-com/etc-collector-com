package ldap

import (
	"context"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// displaySpecifierCodeAttributes are the displaySpecifier attributes that
// carry an executable command line rather than plain display metadata
// (Microsoft Learn, "Display Specifiers" / "Modifying the Context Menu" -
// Win32/AD admin consoles run the value of adminContextMenu/contextMenu, and
// creationWizard/adminPropertyPages/shellPropertyPages register DLLs the same
// consoles load). A change to any other attribute on a displaySpecifier
// object is cosmetic and out of scope for SI000082.
var displaySpecifierCodeAttributes = map[string]bool{
	"admincontextmenu":   true,
	"contextmenu":        true,
	"creationwizard":     true,
	"adminpropertypages": true,
	"shellpropertypages": true,
}

func isDisplaySpecifierCodeAttribute(attrName string) bool {
	return displaySpecifierCodeAttributes[strings.ToLower(attrName)]
}

// filterDisplaySpecifierChanges is the pure decision logic (no I/O, fully
// unit-testable): given the leaf DNs enumerated by GetDisplaySpecifierObjects
// and their already-fetched replication metadata, return the DNs whose
// code-bearing attribute changed after cutoff - in leafDNs order.
func filterDisplaySpecifierChanges(leafDNs []string, metaByDN map[string][]audit.ReplMetadataEntry, cutoff time.Time) []string {
	var changed []string
	for _, dn := range leafDNs {
		for _, m := range metaByDN[dn] {
			if !isDisplaySpecifierCodeAttribute(m.AttributeName) {
				continue
			}
			if !m.LastChangeTime.IsZero() && m.LastChangeTime.After(cutoff) {
				changed = append(changed, dn)
				break // one qualifying attribute is enough to flag this object
			}
		}
	}
	return changed
}

// GetDisplaySpecifierChangesSince orchestrates the live lookup: enumerate
// displaySpecifier leaf objects, fetch each one's replication metadata, then
// apply filterDisplaySpecifierChanges. Replaces a hardcoded probe of 7 locale
// CONTAINER DNs (which never carry the code attributes - those live on the
// leaf objects the containers hold) with real leaf enumeration.
func (c *Client) GetDisplaySpecifierChangesSince(ctx context.Context, cutoff time.Time) ([]string, error) {
	leafDNs, err := c.GetDisplaySpecifierObjects(ctx)
	if err != nil {
		return nil, err
	}

	metaByDN := make(map[string][]audit.ReplMetadataEntry, len(leafDNs))
	for _, dn := range leafDNs {
		meta, err := c.GetReplMetadata(ctx, dn)
		if err != nil {
			continue
		}
		metaByDN[dn] = meta
	}

	return filterDisplaySpecifierChanges(leafDNs, metaByDN, cutoff), nil
}
