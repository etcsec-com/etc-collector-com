package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/catalog"
)

var (
	catalogPlatform string
	catalogOutput   string
)

// platformNames returns catalog.AllPlatforms as plain strings, in order.
// Every user-facing list of accepted --platform values is built from this
// rather than hardcoded, so it can't drift when a platform is added.
func platformNames() []string {
	names := make([]string, len(catalog.AllPlatforms))
	for i, p := range catalog.AllPlatforms {
		names[i] = string(p)
	}
	return names
}

// auditCatalogCmd renders the vulnerability catalog markdown for one platform
// from the runtime detector registry. Used by `make catalog` to regenerate
// docs/vulnerabilities/{active-directory,azure,exchange,intune,google}/*.md
// without anyone writing markdown by hand. The committed files must match
// this output byte-for-byte - TestCatalogIsStable enforces it.
var auditCatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Render the vulnerability catalog markdown from the detector registry",
	Long: `Generate a per-platform vulnerability catalog markdown from the runtime
detector registry. Iterates audit.DefaultRegistry, calls Doc() on each
detector, and renders the markdown via the embedded template.

Use --platform to choose which one (see catalog.AllPlatforms for the full
list). With --output, writes the file directly; without it, emits to stdout.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		platform := catalog.Platform(catalogPlatform)
		valid := false
		for _, p := range catalog.AllPlatforms {
			if platform == p {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("--platform must be one of %s, got %q", strings.Join(platformNames(), ", "), catalogPlatform)
		}
		out, err := catalog.Generate(audit.DefaultRegistry, platform, Version)
		if err != nil {
			return err
		}
		if catalogOutput == "" || catalogOutput == "-" {
			_, err = os.Stdout.WriteString(out)
			return err
		}
		if err := os.WriteFile(catalogOutput, []byte(out), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", catalogOutput, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(out), catalogOutput)
		return nil
	},
}

func init() {
	platformHelp := fmt.Sprintf("Platform: one of %s (required)", strings.Join(platformNames(), ", "))
	auditCatalogCmd.Flags().StringVar(&catalogPlatform, "platform", "", platformHelp)
	auditCatalogCmd.Flags().StringVarP(&catalogOutput, "output", "o", "", "Output file (default: stdout)")
	_ = auditCatalogCmd.MarkFlagRequired("platform")
	auditCmd.AddCommand(auditCatalogCmd)
}
