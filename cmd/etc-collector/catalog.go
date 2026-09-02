package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/catalog"
)

var (
	catalogPlatform string
	catalogOutput   string
)

// auditCatalogCmd renders the vulnerability catalog markdown for one platform
// from the runtime detector registry. Used by `make catalog` to regenerate
// docs/vulnerabilities/{active-directory,azure}/*.md without anyone writing
// markdown by hand. The committed files must match this output byte-for-byte
// — TestCatalogIsStable enforces it.
var auditCatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Render the vulnerability catalog markdown from the detector registry",
	Long: `Generate the AD or Azure vulnerability catalog markdown from the runtime
detector registry. Iterates audit.DefaultRegistry, calls Doc() on each
detector, and renders the markdown via the embedded template.

Use --platform=ad or --platform=azure to choose. With --output, writes the
file directly; without it, emits to stdout.

Build with -tags pro to include Pro-only detectors (ESC1-11, attack paths,
Azure risk protection) — otherwise they won't appear in the output.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var platform catalog.Platform
		switch catalogPlatform {
		case "ad":
			platform = catalog.PlatformAD
		case "azure":
			platform = catalog.PlatformAzure
		default:
			return fmt.Errorf("--platform must be 'ad' or 'azure', got %q", catalogPlatform)
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
	auditCatalogCmd.Flags().StringVar(&catalogPlatform, "platform", "", "Platform: 'ad' or 'azure' (required)")
	auditCatalogCmd.Flags().StringVarP(&catalogOutput, "output", "o", "", "Output file (default: stdout)")
	_ = auditCatalogCmd.MarkFlagRequired("platform")
	auditCmd.AddCommand(auditCatalogCmd)
}
