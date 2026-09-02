package catalog

import (
	"bytes"
	"embed"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

//go:embed templates/*.md.tmpl
var tmplFS embed.FS

// CategoryDisplayOrder defines the deterministic ordering used for AD/Azure
// catalogs. Categories not listed here go alphabetically at the end. Mirrors
// the historical ordering of the manually-maintained markdown so the
// regenerated output is intuitive for readers.
var CategoryDisplayOrder = []audit.DetectorCategory{
	// AD
	audit.CategoryPassword, audit.CategoryKerberos, audit.CategoryAccounts,
	audit.CategoryGroups, audit.CategoryComputers, audit.CategoryAdvanced,
	audit.CategoryPermissions, audit.CategoryADCS, audit.CategoryGPO,
	audit.CategoryTrusts, audit.CategoryAttackPaths, audit.CategoryMonitoring,
	audit.CategoryCompliance, audit.CategoryNetwork,
	// Azure
	audit.CategoryIdentity, audit.CategoryApplications,
	audit.CategoryConditionalAccess, audit.CategoryPrivilegedAccess,
	audit.CategoryGuestExternal, audit.CategoryConfig,
	audit.CategoryRiskProtection, audit.CategoryAzureCompliance,
}

// CategoryDisplayName returns the human-friendly name shown in the catalog
// markdown headers. Falls back to the raw enum value for unknown categories.
func CategoryDisplayName(c audit.DetectorCategory) string {
	switch c {
	case audit.CategoryPassword:
		return "Password"
	case audit.CategoryKerberos:
		return "Kerberos"
	case audit.CategoryAccounts:
		return "Accounts"
	case audit.CategoryGroups:
		return "Groups"
	case audit.CategoryComputers:
		return "Computers"
	case audit.CategoryAdvanced:
		return "Advanced"
	case audit.CategoryPermissions:
		return "Permissions"
	case audit.CategoryADCS:
		return "ADCS"
	case audit.CategoryGPO:
		return "GPO"
	case audit.CategoryTrusts:
		return "Trusts"
	case audit.CategoryAttackPaths:
		return "Attack Paths"
	case audit.CategoryMonitoring:
		return "Monitoring"
	case audit.CategoryCompliance:
		return "Compliance"
	case audit.CategoryNetwork:
		return "Network"
	case audit.CategoryIdentity:
		return "Identity"
	case audit.CategoryApplications:
		return "Applications"
	case audit.CategoryConditionalAccess:
		return "Conditional Access"
	case audit.CategoryPrivilegedAccess:
		return "Privileged Access"
	case audit.CategoryGuestExternal:
		return "Guest External"
	case audit.CategoryConfig:
		return "Config"
	case audit.CategoryRiskProtection:
		return "Risk Protection"
	case audit.CategoryAzureCompliance:
		return "Compliance"
	}
	return string(c)
}

// rowVM is one row in the per-category table.
type rowVM struct {
	N           int
	ID          string
	Severity    string
	Weight      string
	Title       string
	Description string
	SourceFile  string
}

// categoryVM groups detectors by category for the template.
type categoryVM struct {
	Name              string
	Count             int
	SeverityHistogram string
	Detectors         []rowVM
}

// catalogVM is the full template input.
type catalogVM struct {
	Total            int
	CategoryCount    int
	CollectorVersion string
	Categories       []categoryVM
}

// Generate renders the catalog markdown for one platform from the registry.
// Output is fully deterministic (categories sorted by CategoryDisplayOrder,
// detectors within a category sorted alphabetically by ID, sequential
// numbering across categories).
func Generate(reg *audit.Registry, platform Platform, version string) (string, error) {
	all := reg.All()

	// Filter by platform.
	var filtered []audit.Detector
	for _, d := range all {
		if PlatformOf(d) != platform {
			continue
		}
		filtered = append(filtered, d)
	}
	if len(filtered) == 0 {
		return "", fmt.Errorf("no detectors registered for platform %q", platform)
	}

	// Group by category.
	byCat := map[audit.DetectorCategory][]audit.Detector{}
	for _, d := range filtered {
		byCat[d.Category()] = append(byCat[d.Category()], d)
	}

	// Build display-ordered category list.
	seenCats := map[audit.DetectorCategory]bool{}
	var orderedCats []audit.DetectorCategory
	for _, c := range CategoryDisplayOrder {
		if _, ok := byCat[c]; ok {
			orderedCats = append(orderedCats, c)
			seenCats[c] = true
		}
	}
	// Append any unlisted categories alphabetically (defensive — shouldn't happen).
	var leftovers []audit.DetectorCategory
	for c := range byCat {
		if !seenCats[c] {
			leftovers = append(leftovers, c)
		}
	}
	sort.Slice(leftovers, func(i, j int) bool { return leftovers[i] < leftovers[j] })
	orderedCats = append(orderedCats, leftovers...)

	// Build categoryVM list with sequential numbering across all categories.
	n := 1
	cats := make([]categoryVM, 0, len(orderedCats))
	for _, c := range orderedCats {
		dets := byCat[c]
		sort.Slice(dets, func(i, j int) bool { return dets[i].ID() < dets[j].ID() })
		rows := make([]rowVM, 0, len(dets))
		histo := map[types.Severity]int{}
		for _, d := range dets {
			doc := d.Doc()
			rows = append(rows, rowVM{
				N:           n,
				ID:          d.ID(),
				Severity:    capitalize(string(doc.Severity)),
				Weight:      formatWeight(doc.Weight()),
				Title:       escapeForTableCell(doc.Title),
				Description: escapeForTableCell(doc.Description),
				SourceFile:  doc.SourceFile,
			})
			histo[doc.Severity]++
			n++
		}
		cats = append(cats, categoryVM{
			Name:              CategoryDisplayName(c),
			Count:             len(dets),
			SeverityHistogram: severityHistogram(histo),
			Detectors:         rows,
		})
	}

	vm := catalogVM{
		Total:            len(filtered),
		CategoryCount:    len(cats),
		CollectorVersion: version,
		Categories:       cats,
	}

	tmplName := "ad_catalog.md.tmpl"
	if platform == PlatformAzure {
		tmplName = "azure_catalog.md.tmpl"
	}
	tmpl, err := template.ParseFS(tmplFS, "templates/"+tmplName)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vm); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// formatWeight prints the float weight without trailing ".0" for integer
// values (10, 3, 1, 0) and "0.2" for SeverityLow.
func formatWeight(w float64) string {
	if w == float64(int(w)) {
		return fmt.Sprintf("%d", int(w))
	}
	return fmt.Sprintf("%g", w)
}

// escapeForTableCell turns markdown-breaking characters into safe ones so
// the generated row stays a valid pipe table cell. We keep prose intact;
// only `|` and newlines need handling.
func escapeForTableCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.TrimSpace(s)
}

// severityHistogram builds a string like "5 Critical, 2 High, 4 Medium".
// Always lists severities in fixed order, omits zero counts.
func severityHistogram(h map[types.Severity]int) string {
	order := []struct {
		sev   types.Severity
		label string
	}{
		{types.SeverityCritical, "Critical"},
		{types.SeverityHigh, "High"},
		{types.SeverityMedium, "Medium"},
		{types.SeverityLow, "Low"},
		{types.SeverityInfo, "Info"},
	}
	parts := make([]string, 0, 5)
	for _, o := range order {
		if h[o.sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", h[o.sev], o.label))
		}
	}
	return strings.Join(parts, ", ")
}
