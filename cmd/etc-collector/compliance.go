package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/etcsec-com/etc-collector/internal/audit/compliance"
	"github.com/etcsec-com/etc-collector/internal/audit/compliance/catalogs"
)

// complianceCmd is the root verb for compliance-related diagnostics. Today
// it ships a single subcommand `verify` that prints a per-framework fidelity
// report — useful for an ANSSI auditor verifying that ETC's score and the
// underlying catalog are consistent with the published reference document.
var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Compliance catalog diagnostics",
}

var complianceVerifyFramework string

var complianceVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Print catalog metadata and detector coverage for a compliance framework",
	Long: `Print a per-framework summary that an auditor can cross-check against
the official source publication.

Output covers:
  - the source URL (canonical PDF / web page)
  - the version and last fact-check date
  - the total number of controls in the catalog vs. how many ETC actually
    verifies through detector mappings
  - alerts on stretched mappings that were explicitly removed in v3.1.16

Examples:
  etc-collector compliance verify                         # all frameworks
  etc-collector compliance verify --framework ANSSI_PA099 # one framework
`,
	RunE:          runComplianceVerify,
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	rootCmd.AddCommand(complianceCmd)
	complianceCmd.AddCommand(complianceVerifyCmd)

	complianceVerifyCmd.Flags().StringVar(&complianceVerifyFramework, "framework", "", "Restrict output to one framework key (e.g. ANSSI_PA099). Default: all.")
}

func runComplianceVerify(cmd *cobra.Command, args []string) error {
	frameworks := compliance.AllFrameworks
	if complianceVerifyFramework != "" {
		frameworks = []string{complianceVerifyFramework}
	}

	for i, fw := range frameworks {
		if i > 0 {
			fmt.Println()
		}
		if err := printFrameworkReport(fw); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return err
		}
	}
	return nil
}

func printFrameworkReport(fw string) error {
	cat := catalogs.Get(fw)
	if cat == nil {
		return fmt.Errorf("framework %q is not registered", fw)
	}

	totalControls := len(cat.Controls)
	autoControls := 0
	for _, c := range cat.Controls {
		if c.Automatable {
			autoControls++
		}
	}

	mappedDistinct := distinctMappedControls(fw)
	autoMapped := 0
	mappedSet := make(map[string]struct{}, len(mappedDistinct))
	for _, code := range mappedDistinct {
		mappedSet[code] = struct{}{}
	}
	for _, c := range cat.Controls {
		if c.Automatable {
			if _, ok := mappedSet[c.Code]; ok {
				autoMapped++
			}
		}
	}

	covTotal := percent(len(mappedDistinct), totalControls)
	covAuto := percent(autoMapped, autoControls)

	fmt.Printf("Framework         : %s\n", fw)
	fmt.Printf("Source            : %s\n", cat.Source)
	fmt.Printf("Version           : %s\n", cat.Version)
	if cat.FetchedAt != "" {
		fmt.Printf("Last fact-check   : %s\n", cat.FetchedAt)
	} else {
		fmt.Printf("Last fact-check   : (none)\n")
	}
	fmt.Printf("Total controls    : %d\n", totalControls)
	fmt.Printf("Automatable       : %d\n", autoControls)
	fmt.Printf("Mapped (distinct) : %d (covers %s of total, %s of automatable)\n", len(mappedDistinct), covTotal, covAuto)

	// Stretched alerts: count how many of the catalog's controls have an
	// OfficialFR (= traceable). For ANSSI catalogs the test suite already
	// guarantees 100%; for non-ANSSI catalogs this just reports the gap.
	withFR := 0
	for _, c := range cat.Controls {
		if c.OfficialFR != "" {
			withFR++
		}
	}
	fmt.Printf("With OfficialFR   : %d / %d\n", withFR, totalControls)

	// Print the list of mapped controls (sorted) so the auditor can scan.
	if len(mappedDistinct) > 0 {
		sort.Strings(mappedDistinct)
		fmt.Printf("Mapped codes      : %s\n", strings.Join(mappedDistinct, ", "))
	}

	return nil
}

// distinctMappedControls returns the unique Control codes referenced in
// mappings.go for the given framework. It uses the public API surface
// from the compliance package so it stays in sync with the score logic.
func distinctMappedControls(fw string) []string {
	seen := make(map[string]struct{})
	for _, ms := range compliance.Mappings() {
		for _, m := range ms {
			if m.Framework == fw {
				seen[m.Control] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	return out
}

func percent(num, denom int) string {
	if denom == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", float64(num)/float64(denom)*100)
}
