// Package smb provides an SMB client for reading SYSVOL GPO data
package smb

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Config holds SMB connection configuration
type Config struct {
	Server   string
	Domain   string
	Username string
	Password string
	Port     int
	Timeout  time.Duration
}

// Client provides read-only access to SYSVOL via SMB
type Client struct {
	config  Config
	session *smb2.Session
	share   *smb2.Share
	conn    net.Conn
}

// NewClient creates a new SMB client
func NewClient(cfg Config) *Client {
	if cfg.Port == 0 {
		cfg.Port = 445
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Client{config: cfg}
}

// Connect establishes SMB connection and mounts SYSVOL
func (c *Client) Connect(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", c.config.Server, c.config.Port)

	dialer := net.Dialer{Timeout: c.config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smb: dial %s: %w", addr, err)
	}
	c.conn = conn

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     c.config.Username,
			Password: c.config.Password,
			Domain:   c.config.Domain,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smb: session: %w", err)
	}
	c.session = session

	share, err := session.Mount("SYSVOL")
	if err != nil {
		session.Logoff()
		conn.Close()
		return fmt.Errorf("smb: mount SYSVOL: %w", err)
	}
	c.share = share

	return nil
}

// Close closes the SMB connection
func (c *Client) Close() error {
	if c.share != nil {
		c.share.Umount()
	}
	if c.session != nil {
		c.session.Logoff()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}

// ReadFile reads a file from the SYSVOL share
func (c *Client) ReadFile(path string) ([]byte, error) {
	f, err := c.share.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// ListDir lists entries in a directory
func (c *Client) ListDir(path string) ([]fs.FileInfo, error) {
	entries, err := c.share.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var infos []fs.FileInfo
	for _, e := range entries {
		infos = append(infos, e)
	}
	return infos, nil
}

// FileExists checks if a file/directory exists
func (c *Client) FileExists(path string) bool {
	_, err := c.share.Stat(path)
	return err == nil
}

// CollectGPOPolicies reads and parses GPO policy files from SYSVOL
func (c *Client) CollectGPOPolicies(gpos []types.GPO, domainName string) map[string]*audit.GPOPolicy {
	policies := make(map[string]*audit.GPOPolicy)

	for _, gpo := range gpos {
		guid := gpo.GUID
		if guid == "" {
			guid = gpo.CN
		}
		if guid == "" {
			continue
		}

		policy := &audit.GPOPolicy{
			GUID:        guid,
			DisplayName: gpo.DisplayName,
		}

		// Build the SYSVOL path for this GPO
		// SYSVOL structure: {domain}\Policies\{GUID}\...
		basePath := filepath.Join(domainName, "Policies", guid)

		// Parse GptTmpl.inf
		gptTmplPath := filepath.Join(basePath, "Machine", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")
		if data, err := c.ReadFile(gptTmplPath); err == nil {
			kp, sa, ea, pr, rs, rg := ParseGptTmpl(data)
			policy.KerberosPolicy = kp
			policy.SystemAccess = sa
			policy.EventAudit = ea
			policy.PrivilegeRights = pr
			if rs != nil {
				policy.RegistrySettings = rs
			}
			if len(rg) > 0 {
				policy.RestrictedGroups = rg
			}
		}

		// Parse Registry.pol (merges with/overrides GptTmpl.inf registry values)
		regPolPath := filepath.Join(basePath, "Machine", "Registry.pol")
		if data, err := c.ReadFile(regPolPath); err == nil {
			regPol := ParseRegistryPol(data)
			if regPol != nil {
				if policy.RegistrySettings == nil {
					policy.RegistrySettings = regPol
				} else {
					mergeRegistrySettings(policy.RegistrySettings, regPol)
				}
			}
		}

		// T_132/D3 — parse audit.csv (Advanced Audit Policy Configuration).
		// Independent of GptTmpl.inf's [Event Audit] (EventAudit above): a
		// GPO can carry either, both, or neither, and there's no merge
		// between them — compliance/auditpolicy resolves which one to
		// trust per check.
		auditCSVPath := filepath.Join(basePath, "Machine", "Microsoft", "Windows NT", "Audit", "audit.csv")
		if data, err := c.ReadFile(auditCSVPath); err == nil {
			if adv := parseAuditCSV(data); adv != nil {
				policy.AdvancedAudit = adv
			}
		}

		policies[guid] = policy
	}

	return policies
}

// ScanSYSVOL scans for cpassword vulnerabilities and orphaned GPOs
func (c *Client) ScanSYSVOL(gpos []types.GPO, domainName string) []audit.SYSVOLFinding {
	var findings []audit.SYSVOLFinding

	// Build set of known GPO GUIDs from LDAP
	knownGUIDs := make(map[string]string) // GUID -> DisplayName
	for _, gpo := range gpos {
		guid := gpo.GUID
		if guid == "" {
			guid = gpo.CN
		}
		if guid != "" {
			knownGUIDs[strings.ToUpper(guid)] = gpo.DisplayName
		}
	}

	policiesPath := filepath.Join(domainName, "Policies")

	// Scan each GPO directory in SYSVOL
	entries, err := c.ListDir(policiesPath)
	if err != nil {
		return findings
	}

	// Track SYSVOL GUIDs for orphan detection
	sysvolGUIDs := make(map[string]bool)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()
		if !strings.HasPrefix(dirName, "{") {
			continue
		}
		upperGUID := strings.ToUpper(dirName)
		sysvolGUIDs[upperGUID] = true

		gpoBasePath := filepath.Join(policiesPath, dirName)
		displayName := knownGUIDs[upperGUID]

		// Scan for cpassword in Group Policy Preferences XML files
		cpasswordFindings := c.scanForCPassword(gpoBasePath, dirName, displayName)
		findings = append(findings, cpasswordFindings...)

		// v3.1.18 — scan GPO logon/logoff scripts for cleartext secrets
		// (ANSSI PA-099 R31). Adds Type="script_secret" findings.
		scriptFindings := c.scanForScriptSecrets(gpoBasePath, dirName, displayName)
		findings = append(findings, scriptFindings...)

		// Check for orphaned SYSVOL (directory exists but no LDAP object)
		if _, exists := knownGUIDs[upperGUID]; !exists {
			findings = append(findings, audit.SYSVOLFinding{
				Type:     "orphaned_sysvol",
				GPOGUID:  dirName,
				FilePath: gpoBasePath,
				Details:  "SYSVOL directory exists without corresponding LDAP GPO object",
			})
		}
	}

	// Check for orphaned LDAP (LDAP object exists but no SYSVOL directory)
	for guid, name := range knownGUIDs {
		if !sysvolGUIDs[guid] {
			findings = append(findings, audit.SYSVOLFinding{
				Type:    "orphaned_ldap",
				GPOGUID: guid,
				GPOName: name,
				Details: "LDAP GPO object exists without corresponding SYSVOL directory",
			})
		}
	}

	return findings
}

// scanForCPassword scans GPO Preferences XML files for cpassword attributes
func (c *Client) scanForCPassword(gpoBasePath, guid, displayName string) []audit.SYSVOLFinding {
	var findings []audit.SYSVOLFinding

	// GPP XML files that may contain cpassword (MS14-025)
	prefPaths := []string{
		filepath.Join("Machine", "Preferences", "Groups", "Groups.xml"),
		filepath.Join("Machine", "Preferences", "Services", "Services.xml"),
		filepath.Join("Machine", "Preferences", "ScheduledTasks", "ScheduledTasks.xml"),
		filepath.Join("Machine", "Preferences", "DataSources", "DataSources.xml"),
		filepath.Join("Machine", "Preferences", "Drives", "Drives.xml"),
		filepath.Join("Machine", "Preferences", "Printers", "Printers.xml"),
		filepath.Join("User", "Preferences", "Groups", "Groups.xml"),
		filepath.Join("User", "Preferences", "Services", "Services.xml"),
		filepath.Join("User", "Preferences", "ScheduledTasks", "ScheduledTasks.xml"),
		filepath.Join("User", "Preferences", "DataSources", "DataSources.xml"),
		filepath.Join("User", "Preferences", "Drives", "Drives.xml"),
		filepath.Join("User", "Preferences", "Printers", "Printers.xml"),
	}

	for _, relPath := range prefPaths {
		fullPath := filepath.Join(gpoBasePath, relPath)
		data, err := c.ReadFile(fullPath)
		if err != nil {
			continue // File doesn't exist, skip
		}

		// Check for cpassword attribute in the XML
		content := string(data)
		if containsCPassword(content) {
			findings = append(findings, audit.SYSVOLFinding{
				Type:     "cpassword",
				GPOGUID:  guid,
				GPOName:  displayName,
				FilePath: fullPath,
				Details:  fmt.Sprintf("cpassword found in %s (MS14-025)", filepath.Base(relPath)),
			})
		}
	}

	return findings
}

// scriptSecretPatterns is the conservative set of regex-like substring tests
// applied to logon/logoff script bodies under the GPO Scripts subtree.
// Conservative on purpose: ANSSI R31 wants secrets in scripts flagged, but
// false positives (commented-out examples, variable names without values)
// would make the report unusable. Patterns must match a value, not just a
// keyword.
//
// v3.1.18 — added to back the ANSSI_R31_SCRIPT_SECRETS detector with real
// data instead of an extension-only filter on cpassword findings.
var scriptSecretPatterns = []scriptPattern{
	{"PowerShell ConvertTo-SecureString -AsPlainText -Force", "convertto-securestring", "-asplaintext"},
	{"Hardcoded $cred = ...", "$cred =", ""},
	{"Cleartext password= assignment", "password=", ""},
	{"net user with inline password", "net user ", " /add"},
	{"runas /user with password", "runas /user:", "/savecred"},
	{"psexec with -p", "psexec", "-p "},
}

type scriptPattern struct {
	Description string
	MustContain string
	AlsoContain string // optional second token; empty = single-pattern check
}

// scriptSecretExtensions enumerates the file extensions ANSSI R31 explicitly
// references (PowerShell, batch, VBS). Lowercase, with leading dot.
var scriptSecretExtensions = []string{".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".wsf"}

// scanForScriptSecrets walks GPO Scripts directories under both Machine\Scripts
// and User\Scripts (Startup, Shutdown, Logon, Logoff). For each script file
// matching scriptSecretExtensions, it greps for scriptSecretPatterns. Each
// match emits a SYSVOLFinding{Type:"script_secret"} consumed by R31.
func (c *Client) scanForScriptSecrets(gpoBasePath, guid, displayName string) []audit.SYSVOLFinding {
	var findings []audit.SYSVOLFinding

	scriptDirs := []string{
		filepath.Join("Machine", "Scripts", "Startup"),
		filepath.Join("Machine", "Scripts", "Shutdown"),
		filepath.Join("User", "Scripts", "Logon"),
		filepath.Join("User", "Scripts", "Logoff"),
	}

	for _, rel := range scriptDirs {
		dirPath := filepath.Join(gpoBasePath, rel)
		entries, err := c.ListDir(dirPath)
		if err != nil {
			continue // directory absent → no scripts in this hook
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			low := strings.ToLower(e.Name())
			isScript := false
			for _, ext := range scriptSecretExtensions {
				if strings.HasSuffix(low, ext) {
					isScript = true
					break
				}
			}
			if !isScript {
				continue
			}
			fullPath := filepath.Join(dirPath, e.Name())
			data, err := c.ReadFile(fullPath)
			if err != nil {
				continue
			}
			content := strings.ToLower(string(data))
			for _, pat := range scriptSecretPatterns {
				if !strings.Contains(content, pat.MustContain) {
					continue
				}
				if pat.AlsoContain != "" && !strings.Contains(content, pat.AlsoContain) {
					continue
				}
				findings = append(findings, audit.SYSVOLFinding{
					Type:     "script_secret",
					GPOGUID:  guid,
					GPOName:  displayName,
					FilePath: fullPath,
					Details:  pat.Description,
				})
				break // one finding per file is enough
			}
		}
	}

	return findings
}

// containsCPassword checks if XML content contains a non-empty cpassword attribute
func containsCPassword(content string) bool {
	lower := strings.ToLower(content)
	idx := strings.Index(lower, "cpassword=\"")
	if idx == -1 {
		return false
	}
	// Check that the value is not empty: cpassword=""
	valueStart := idx + len("cpassword=\"")
	if valueStart >= len(content) {
		return false
	}
	return content[valueStart] != '"'
}

// mergeRegistrySettings merges src into dst (src values override dst where set).
//
// T_132/D1: this used to be an explicit 8-field whitelist that silently
// dropped the other 32 fields of RegistrySettings whenever a GPO carried
// both a GptTmpl.inf and a Registry.pol — the normal shape for a real
// Default Domain Controllers Policy, not an edge case. Every field of
// RegistrySettings is a pointer (*int or *string), so the merge is done
// generically over all of them by reflection: a field added to the struct
// is merged automatically, with no whitelist left to fall out of sync.
func mergeRegistrySettings(dst, src *audit.RegistrySettings) {
	dstVal := reflect.ValueOf(dst).Elem()
	srcVal := reflect.ValueOf(src).Elem()
	for i := 0; i < srcVal.NumField(); i++ {
		srcField := srcVal.Field(i)
		if srcField.Kind() != reflect.Ptr || srcField.IsNil() {
			continue
		}
		dstVal.Field(i).Set(srcField)
	}
}

// WalkDir walks a directory tree on the SMB share
func (c *Client) WalkDir(root string, fn func(path string, info os.FileInfo, err error) error) error {
	entries, err := c.ListDir(root)
	if err != nil {
		return fn(root, nil, err)
	}

	for _, info := range entries {
		path := filepath.Join(root, info.Name())
		if info.IsDir() {
			if err := c.WalkDir(path, fn); err != nil {
				return err
			}
		} else {
			if err := fn(path, info, nil); err != nil {
				return err
			}
		}
	}

	return nil
}
