package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit/discovery"
	"github.com/etcsec-com/etc-collector/internal/providers/ldap"
	"github.com/spf13/cobra"
)

// Discover-specific flags
var (
	discoverSampleSize          int
	discoverFormat              string
	discoverOutput              string
	discoverFullListing         bool
	discoverIncludeGroupMembers string // "", "true", "false" — tri-state so we can detect "not set"
)

// discoverCmd is the parent for `discover` subcommands.
var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "List assets in an identity provider (read-only, no detectors)",
	Long: `Inventory assets (OUs, users, computers, groups) without running security detectors.

Use the manifest to build an exclusions.yaml config, then run ` + "`audit ad --exclusions exclusions.yaml`" + `.

Example:
  etc-collector discover ad \
    --ldap-url ldaps://dc:636 \
    --ldap-bind-dn "CN=admin,CN=Users,DC=example,DC=com" \
    --ldap-bind-password secret \
    --ldap-base-dn DC=example,DC=com \
    -o assets.json`,
}

// discoverADCmd runs the AD inventory.
var discoverADCmd = &cobra.Command{
	Use:   "ad",
	Short: "Discover Active Directory assets (on-premises)",
	Long:  `Enumerate users, computers, groups and OUs from an on-premises AD via LDAP. Produces a JSON manifest with counts and sample DNs so an auditor can design asset-filter rules.`,
	RunE:  runDiscoverAD,
}

func init() {
	rootCmd.AddCommand(discoverCmd)
	discoverCmd.AddCommand(discoverADCmd)

	discoverCmd.PersistentFlags().IntVar(&discoverSampleSize, "sample-size", 50, "Max DN samples returned per asset type (ignored when --full-listing)")
	discoverCmd.PersistentFlags().BoolVar(&discoverFullListing, "full-listing", false, "Return every user/computer/group/OU instead of a capped sample (large output)")
	discoverCmd.PersistentFlags().StringVar(&discoverIncludeGroupMembers, "include-group-members", "", "Include direct member DNs on each group sample (true|false; default: matches --full-listing)")
	discoverCmd.PersistentFlags().StringVar(&discoverFormat, "format", "json", "Output format: json, json-pretty, tree")
	discoverCmd.PersistentFlags().StringVarP(&discoverOutput, "output", "o", "", "Output file (default: stdout)")

	// Re-use the AD LDAP flags defined in audit.go via persistent lookups.
	discoverADCmd.Flags().StringVar(&auditLDAPURL, "ldap-url", "", "LDAP server URL (e.g., ldaps://dc:636) [env: LDAP_URL]")
	discoverADCmd.Flags().StringVar(&auditLDAPBindDN, "ldap-bind-dn", "", "LDAP bind DN [env: LDAP_BIND_DN]")
	discoverADCmd.Flags().StringVar(&auditLDAPBindPass, "ldap-bind-password", "", "LDAP bind password [env: LDAP_BIND_PASSWORD]")
	discoverADCmd.Flags().StringVar(&auditLDAPBaseDN, "ldap-base-dn", "", "LDAP base DN [env: LDAP_BASE_DN]")
	discoverADCmd.Flags().BoolVar(&auditLDAPTLSVerify, "ldap-tls-verify", true, "Verify LDAP TLS certificates [env: LDAP_TLS_VERIFY]")
	discoverADCmd.Flags().StringVar(&auditLDAPCACert, "ldap-ca-cert", "", "Path to a PEM file containing the CA that signed the DC certificate")
	discoverADCmd.Flags().StringVar(&auditLDAPTLSMinVersion, "ldap-tls-min-version", "", "Minimum TLS version for LDAPS/StartTLS: 1.0, 1.1, 1.2, 1.3")
	discoverADCmd.Flags().BoolVar(&auditLDAPStartTLS, "ldap-start-tls", false, "Use StartTLS to upgrade an ldap:// connection to TLS")
	// T_111: deliberately NOT MarkFlagRequired anymore — same reasoning as
	// audit.go's auditADCmd (see the comment there): cobra would reject a
	// missing flag before LDAP_*/config.yaml resolution ever runs.
	// requireLDAPConn (audit.go) enforces the requirement after resolution.
}

func runDiscoverAD(cmd *cobra.Command, args []string) error {
	// T_106 (follow-up to T_101/server.go): --ldap-bind-password puts the LDAP
	// bind secret in argv, readable by any local user via /proc/<pid>/cmdline
	// (world-readable on Linux) for as long as the process runs. T_111 wired
	// LDAP_BIND_PASSWORD/ldap.bindPassword as real fallbacks below (see
	// resolveLDAPConnFromSources in audit.go) — this flag stays supported for
	// backward compatibility with existing invocations, same as server.go.
	if cmd.Flags().Changed("ldap-bind-password") {
		log.Warn("--ldap-bind-password was passed on the command line — the secret is readable by any local user for as long as this process runs (e.g. via /proc/<pid>/cmdline on Linux). Prefer the LDAP_BIND_PASSWORD environment variable or ldap.bindPassword in config.yaml instead.")
	}

	// T_111: same CLI flag > LDAP_* env var > config.yaml precedence as
	// runAuditAD — see resolveLDAPConnFromSources's doc comment in audit.go.
	conn := resolveLDAPConnFromSources(auditLDAPURL, auditLDAPBindDN, auditLDAPBindPass, auditLDAPBaseDN)
	if err := requireLDAPConn(conn); err != nil {
		return err
	}
	tlsVerify := resolveLDAPTLSVerify(cmd, auditLDAPTLSVerify)

	log.Info("Starting AD asset discovery", "ldap_url", conn.URL, "base_dn", conn.BaseDN)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Resolve TLS extras: CLI flag > env var > YAML config.
	caCert := firstNonEmpty(auditLDAPCACert, os.Getenv("LDAP_TLS_CA_CERT"), configLDAPField("TLSCACert"))
	caCertPEM := firstNonEmpty(os.Getenv("LDAP_TLS_CA_CERT_PEM"), configLDAPField("TLSCACertPEM"))
	tlsMin := firstNonEmpty(auditLDAPTLSMinVersion, os.Getenv("LDAP_TLS_MIN_VERSION"), configLDAPField("TLSMinVersion"))
	startTLS := auditLDAPStartTLS || os.Getenv("LDAP_START_TLS") == "true" || configLDAPBool("StartTLS")

	ldapClient, err := ldap.NewClient(ldap.Config{
		URL:           conn.URL,
		BindDN:        conn.BindDN,
		BindPassword:  conn.BindPassword,
		BaseDN:        conn.BaseDN,
		TLSVerify:     tlsVerify,
		TLSCACert:     caCert,
		TLSCACertPEM:  caCertPEM,
		TLSMinVersion: tlsMin,
		StartTLS:      startTLS,
		Timeout:       30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("create LDAP client: %w", err)
	}

	log.Info("Connecting to LDAP...")
	if err := ldapClient.Connect(ctx); err != nil {
		var ce *ldap.ConnectError
		if errors.As(err, &ce) {
			return fmt.Errorf("LDAP connection failed:\n%s", ce.PrettyPrint())
		}
		return fmt.Errorf("connect to LDAP: %w", err)
	}
	defer ldapClient.Close()
	log.Info("LDAP connected")

	var includeMembers *bool
	switch strings.ToLower(discoverIncludeGroupMembers) {
	case "true", "1", "yes":
		t := true
		includeMembers = &t
	case "false", "0", "no":
		f := false
		includeMembers = &f
	}

	log.Info("Enumerating assets...", "fullListing", discoverFullListing, "sampleSize", discoverSampleSize)
	manifest, err := discovery.Run(ctx, ldapClient, discovery.Options{
		SampleSize:          discoverSampleSize,
		FullListing:         discoverFullListing,
		IncludeGroupMembers: includeMembers,
		Progress: func(evt discovery.ProgressEvent) {
			log.Info("discover progress",
				"phase", evt.Phase,
				"elapsedMs", evt.ElapsedMs,
				"users", evt.Counts.Users,
				"groups", evt.Counts.Groups,
				"computers", evt.Counts.Computers,
				"ous", evt.Counts.OUs,
			)
		},
	})
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	log.Info("Discovery completed",
		"users", manifest.Counts.Users,
		"computers", manifest.Counts.Computers,
		"groups", manifest.Counts.Groups,
		"ous", manifest.Counts.OUs,
	)

	return writeDiscoveryOutput(manifest)
}

func writeDiscoveryOutput(m *discovery.Manifest) error {
	var data []byte
	var err error

	switch discoverFormat {
	case "json":
		data, err = json.Marshal(m)
	case "json-pretty":
		data, err = json.MarshalIndent(m, "", "  ")
	case "tree":
		data = []byte(renderTree(m))
	default:
		return fmt.Errorf("unknown format %q (expected: json, json-pretty, tree)", discoverFormat)
	}
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	if discoverFormat != "tree" {
		data = append(data, '\n')
	}

	if discoverOutput == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(discoverOutput, data, 0644); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	log.Info("Manifest written", "file", discoverOutput, "size", len(data))
	return nil
}

// renderTree formats the manifest as a human-readable tree for quick review.
func renderTree(m *discovery.Manifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Domain: %s\n", m.Domain)
	fmt.Fprintf(&b, "Generated: %s\n\n", m.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Counts\n")
	fmt.Fprintf(&b, "  users     : %d\n", m.Counts.Users)
	fmt.Fprintf(&b, "  computers : %d\n", m.Counts.Computers)
	fmt.Fprintf(&b, "  groups    : %d\n", m.Counts.Groups)
	fmt.Fprintf(&b, "  ous       : %d\n\n", m.Counts.OUs)

	fmt.Fprintln(&b, "OU tree (immediate-child counts)")
	for _, r := range m.OUTree {
		renderBranch(&b, r, 0)
	}
	return b.String()
}

func renderBranch(b *strings.Builder, n discovery.OUBranch, depth int) {
	indent := strings.Repeat("  ", depth)
	fmt.Fprintf(b, "%s- %s (users=%d, computers=%d)\n", indent, n.Name, n.Counts.Users, n.Counts.Computers)
	for _, c := range n.Children {
		renderBranch(b, c, depth+1)
	}
}
