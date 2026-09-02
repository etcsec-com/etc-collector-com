// Package ldap provides an LDAP client for Active Directory
package ldap

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Config holds LDAP connection configuration
type Config struct {
	URL           string        `yaml:"url"`
	BindDN        string        `yaml:"bindDN"`
	BindPassword  string        `yaml:"bindPassword"`
	BaseDN        string        `yaml:"baseDN"`
	TLSVerify     bool          `yaml:"tlsVerify"`
	TLSCACert     string        `yaml:"tlsCACert"`     // Path to CA certificate file
	TLSCACertPEM  string        `yaml:"tlsCACertPEM"`  // Inline PEM content (takes precedence over TLSCACert path)
	TLSMinVersion string        `yaml:"tlsMinVersion"` // "1.0", "1.1", "1.2", "1.3"
	StartTLS      bool          `yaml:"startTLS"`      // Use StartTLS on port 389 instead of LDAPS on 636
	Timeout       time.Duration `yaml:"timeout"`
	PageSize      int           `yaml:"pageSize"`

	// AuthMethod selects the bind mechanism. See docs/configuration/
	// ad-integrated-auth.md and the precedence comment on connectInner.
	//   ""/"password" (default) — simple bind with BindDN/BindPassword.
	//     Existing behavior, unchanged (T_047 adds a path, removes none).
	//   "integrated" — Kerberos/SSPI bind under the collector process's own
	//     identity. BindDN/BindPassword are never read on this path — that's
	//     the point of B_036/T_047: no AD secret exists in this config.
	AuthMethod string `yaml:"authMethod"`

	// The fields below apply only when AuthMethod == "integrated".

	// ServicePrincipalName overrides the LDAP SPN used to request the
	// Kerberos service ticket (e.g. "ldap/dc01.example.com"). Empty (the
	// normal case) derives it from the host in URL as "ldap/<host>".
	ServicePrincipalName string `yaml:"servicePrincipalName"`

	// Linux/macOS only (ignored on Windows, which always uses SSPI under the
	// process/service token — see kerberos_windows.go). KerberosKeytab +
	// KerberosPrincipal together select the keytab path: a dedicated service
	// account whose long-term key lives in a keytab file, not requiring an
	// interactive session or a running ticket-granting session. Leave both
	// empty to use the ambient Kerberos credential cache instead — the
	// ticket that kinit, SSSD, or the OS's own Kerberos SSO already
	// populated, resolved from KerberosCCache, then the KRB5CCNAME env var,
	// then the OS default location.
	KerberosKeytab    string `yaml:"kerberosKeytab"`    // path to the keytab file
	KerberosPrincipal string `yaml:"kerberosPrincipal"` // "user@REALM", required when KerberosKeytab is set
	KerberosCCache    string `yaml:"kerberosCCache"`    // explicit ccache path override; normally left empty
	Krb5Config        string `yaml:"krb5Config"`        // path to krb5.conf; empty = OS default (/etc/krb5.conf)
}

// Client implements the Provider interface for LDAP/Active Directory
type Client struct {
	config    Config
	conn      *ldap.Conn
	mu        sync.RWMutex
	connected bool

	// Cached domain info
	domainInfo *types.DomainInfo
}

// NewClient creates a new LDAP client
func NewClient(cfg Config) (*Client, error) {
	// Set defaults
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 1000
	}

	// Validate URL
	if cfg.URL == "" {
		return nil, fmt.Errorf("LDAP URL is required")
	}

	return &Client{
		config: cfg,
	}, nil
}

// Type returns the provider type
func (c *Client) Type() providers.ProviderType {
	return providers.ProviderTypeLDAP
}

// Connect establishes a connection to the LDAP server
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected && c.conn != nil {
		return nil
	}
	return c.connectInner(ctx)
}

// Reconnect closes the existing connection and re-establishes it.
// Safe to call from any goroutine; used by the daemon after an idle timeout.
func (c *Client) Reconnect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connected = false
	return c.connectInner(ctx)
}

// connectInner performs the actual dial + bind. Caller must hold c.mu (write).
func (c *Client) connectInner(_ context.Context) error {
	// Parse URL
	u, err := url.Parse(c.config.URL)
	if err != nil {
		return Classify(err)
	}

	// Build TLS config (used for LDAPS and StartTLS)
	tlsConfig, err := c.buildTLSConfig(strings.Split(u.Host, ":")[0])
	if err != nil {
		return Classify(err)
	}

	// Connect
	var conn *ldap.Conn
	if u.Scheme == "ldaps" && !c.config.StartTLS {
		conn, err = ldap.DialURL(c.config.URL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL(c.config.URL)
	}

	if err != nil {
		return Classify(err)
	}

	// Upgrade to TLS via StartTLS if requested (ldap:// on port 389)
	if c.config.StartTLS && u.Scheme != "ldaps" {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return Classify(err)
		}
	}

	// Set timeout
	conn.SetTimeout(c.config.Timeout)

	// Bind. Precedence is explicit (T_047/B_036): integrated identity wins
	// when AuthMethod == "integrated"; anything else (including the empty
	// default) is the original simple-bind path, unchanged — a config that
	// happens to set both BindPassword and AuthMethod=="integrated" still
	// only takes the integrated path, the password is never read.
	switch c.config.AuthMethod {
	case "integrated":
		if err := c.gssapiBind(conn, strings.Split(u.Host, ":")[0]); err != nil {
			conn.Close()
			return Classify(err)
		}
	default:
		if c.config.BindDN != "" {
			if err := conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
				conn.Close()
				return Classify(err)
			}
		}
	}

	c.conn = conn
	c.connected = true
	return nil
}

// gssapiClient is ldap.GSSAPIClient plus Close(), which every concrete
// implementation we use (gssapi.Client on Linux/macOS, gssapi.SSPIClient on
// Windows) provides but the upstream interface doesn't declare — Close()
// releases the underlying Kerberos/SSPI security context and credentials, a
// step beyond what DeleteSecContext() alone does.
type gssapiClient interface {
	ldap.GSSAPIClient
	Close() error
}

// gssapiBind performs the AuthMethod == "integrated" bind: builds the
// platform GSSAPI client (kerberos.go on Linux/macOS, kerberos_windows.go on
// Windows) and runs the SASL GSSAPI handshake (RFC 4752). host is the bare DC
// hostname parsed from Config.URL, used to derive the default SPN when
// ServicePrincipalName isn't set.
func (c *Client) gssapiBind(conn *ldap.Conn, host string) error {
	client, err := c.newGSSAPIClient()
	if err != nil {
		return fmt.Errorf("integrated auth setup: %w", err)
	}
	defer client.Close() //nolint:errcheck

	spn := c.config.ServicePrincipalName
	if spn == "" {
		spn = "ldap/" + host
	}

	return conn.GSSAPIBind(client, spn, "")
}

// buildTLSConfig creates a TLS configuration from the client config.
// Returns an error when --ldap-tls-min-version is invalid, when
// --ldap-ca-cert points to a missing/unreadable file, or when the CA PEM
// content is malformed. Caller should pass the error through Classify()
// so that the user sees a stable code like LDAP_CA_CERT_FILE_NOT_FOUND.
func (c *Client) buildTLSConfig(serverName string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !c.config.TLSVerify,
		ServerName:         serverName,
	}

	// Set minimum TLS version
	if c.config.TLSMinVersion != "" {
		switch c.config.TLSMinVersion {
		case "1.0":
			tlsConfig.MinVersion = tls.VersionTLS10
		case "1.1":
			tlsConfig.MinVersion = tls.VersionTLS11
		case "1.2":
			tlsConfig.MinVersion = tls.VersionTLS12
		case "1.3":
			tlsConfig.MinVersion = tls.VersionTLS13
		default:
			return nil, fmt.Errorf("invalid --ldap-tls-min-version %q (expected 1.0, 1.1, 1.2 or 1.3)", c.config.TLSMinVersion)
		}
	}

	// Load CA certificate: inline PEM takes precedence over file path
	var caCertPEM []byte
	if c.config.TLSCACertPEM != "" {
		caCertPEM = []byte(c.config.TLSCACertPEM)
	} else if c.config.TLSCACert != "" {
		var err error
		caCertPEM, err = os.ReadFile(c.config.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("read --ldap-ca-cert %q: %w", c.config.TLSCACert, err)
		}
	}
	if len(caCertPEM) > 0 {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertPEM) {
			return nil, fmt.Errorf("--ldap-ca-cert content is not a valid PEM certificate (%d bytes loaded)", len(caCertPEM))
		}
		tlsConfig.RootCAs = caCertPool
		tlsConfig.InsecureSkipVerify = false
	}

	return tlsConfig, nil
}

// TLSDiag contains TLS connection diagnostic information.
type TLSDiag struct {
	BindOK            bool   `json:"bindOK"`
	BaseDNReadable    bool   `json:"baseDNReadable"`
	TLSActive         bool   `json:"tlsActive"`
	TLSVersion        string `json:"tlsVersion,omitempty"`
	CipherSuite       string `json:"cipherSuite,omitempty"`
	ServerCertSubject string `json:"serverCertSubject,omitempty"`
	ServerCertIssuer  string `json:"serverCertIssuer,omitempty"`
	ServerCertExpiry  string `json:"serverCertExpiry,omitempty"`
}

// GetTLSDiag returns TLS and connection diagnostic info for the current connection.
func (c *Client) GetTLSDiag(ctx context.Context) TLSDiag {
	diag := TLSDiag{BindOK: c.connected}
	if !c.connected || c.conn == nil {
		return diag
	}

	// TLS state
	cs, ok := c.conn.TLSConnectionState()
	if ok {
		diag.TLSActive = true
		switch cs.Version {
		case tls.VersionTLS10:
			diag.TLSVersion = "TLS 1.0"
		case tls.VersionTLS11:
			diag.TLSVersion = "TLS 1.1"
		case tls.VersionTLS12:
			diag.TLSVersion = "TLS 1.2"
		case tls.VersionTLS13:
			diag.TLSVersion = "TLS 1.3"
		}
		diag.CipherSuite = tls.CipherSuiteName(cs.CipherSuite)
		if len(cs.PeerCertificates) > 0 {
			cert := cs.PeerCertificates[0]
			diag.ServerCertSubject = cert.Subject.String()
			diag.ServerCertIssuer = cert.Issuer.String()
			diag.ServerCertExpiry = cert.NotAfter.Format("2006-01-02T15:04:05Z")
		}
	}

	// BaseDN readable
	sr := ldap.NewSearchRequest(c.config.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 5, false, "(objectClass=*)", []string{"distinguishedName"}, nil)
	res, err := c.conn.SearchWithPaging(sr, 1)
	diag.BaseDNReadable = err == nil && len(res.Entries) > 0

	return diag
}

// Close closes the LDAP connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connected = false
	return nil
}

// IsConnected returns true if connected
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected && c.conn != nil
}

// isNetworkError returns true when err signals a dead TCP connection that
// can be recovered by reconnecting (go-ldap ErrorNetwork / Result Code 200,
// or "connection closed" / "EOF" / "broken pipe" / "connection reset").
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.ErrorNetwork {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "connection closed") ||
		strings.Contains(s, "Result Code 200") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset by peer")
}

// search performs a paged LDAP search with automatic reconnect on network error.
// If the underlying TCP connection was closed by the DC (idle timeout), it
// transparently reconnects and retries the query once.
func (c *Client) search(ctx context.Context, baseDN, filter string, attrs []string, maxResults int) ([]*ldap.Entry, error) {
	entries, err := c.doPagedSearch(ctx, baseDN, filter, attrs, maxResults)
	if err != nil && isNetworkError(err) {
		if reconnErr := c.Reconnect(ctx); reconnErr == nil {
			entries, err = c.doPagedSearch(ctx, baseDN, filter, attrs, maxResults)
		}
	}
	return entries, err
}

// doPagedSearch is the core paged-search implementation. Caller should use
// search() which adds reconnect-on-network-error on top.
func (c *Client) doPagedSearch(ctx context.Context, baseDN, filter string, attrs []string, maxResults int) ([]*ldap.Entry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Use default base DN if not specified
	if baseDN == "" {
		baseDN = c.config.BaseDN
	}

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // No size limit (we'll handle via paging)
		int(c.config.Timeout.Seconds()),
		false,
		filter,
		attrs,
		nil,
	)

	// Perform paged search
	var entries []*ldap.Entry
	pagingControl := ldap.NewControlPaging(uint32(c.config.PageSize))

	for {
		searchReq.Controls = []ldap.Control{pagingControl}

		result, err := c.conn.Search(searchReq)
		if err != nil {
			return nil, err
		}

		entries = append(entries, result.Entries...)

		// Check if we've hit max results
		if maxResults > 0 && len(entries) >= maxResults {
			entries = entries[:maxResults]
			break
		}

		// Get paging control from response
		ctrl := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if ctrl == nil {
			break
		}

		pagingCtrl, ok := ctrl.(*ldap.ControlPaging)
		if !ok || len(pagingCtrl.Cookie) == 0 {
			break
		}

		pagingControl.SetCookie(pagingCtrl.Cookie)
	}

	return entries, nil
}

// GetUsers retrieves users from Active Directory
func (c *Client) GetUsers(ctx context.Context, opts providers.QueryOptions) ([]types.User, error) {
	filter := opts.Filter
	if filter == "" {
		filter = "(&(objectClass=user)(objectCategory=person))"
	}

	attrs := opts.Attributes
	if len(attrs) == 0 {
		attrs = userAttributes
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, opts.MaxResults)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get users", err)
	}

	users := make([]types.User, 0, len(entries))
	for _, entry := range entries {
		user := parseUser(entry)
		users = append(users, user)
	}

	return users, nil
}

// GetGroups retrieves groups from Active Directory
func (c *Client) GetGroups(ctx context.Context, opts providers.QueryOptions) ([]types.Group, error) {
	filter := opts.Filter
	if filter == "" {
		filter = "(objectClass=group)"
	}

	attrs := opts.Attributes
	if len(attrs) == 0 {
		attrs = groupAttributes
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, opts.MaxResults)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get groups", err)
	}

	groups := make([]types.Group, 0, len(entries))
	for _, entry := range entries {
		group := parseGroup(entry)
		groups = append(groups, group)
	}

	return groups, nil
}

// GetComputers retrieves computer accounts from Active Directory
func (c *Client) GetComputers(ctx context.Context, opts providers.QueryOptions) ([]types.Computer, error) {
	filter := opts.Filter
	if filter == "" {
		filter = "(objectClass=computer)"
	}

	attrs := opts.Attributes
	if len(attrs) == 0 {
		attrs = computerAttributes
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, opts.MaxResults)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get computers", err)
	}

	computers := make([]types.Computer, 0, len(entries))
	for _, entry := range entries {
		computer := parseComputer(entry)
		computers = append(computers, computer)
	}

	return computers, nil
}

// crossRefFilter builds the filter that locates the crossRef partition object
// whose nCName is our naming context (used to read nETBIOSName).
//
// baseDN comes from the cloud (UPDATE_CONFIG_AD / TEST_CONNECTION_AD), so it is
// escaped with ldap.EscapeFilter before interpolation — same idiom as the
// distinguishedName lookups in LookupBatch.
func crossRefFilter(baseDN string) string {
	return fmt.Sprintf("(&(objectClass=crossRef)(nCName=%s))", ldap.EscapeFilter(baseDN))
}

// maxPwdAgeNeverExpiresDays is what filetimeMaxPwdAgeToDays reports for AD's
// "passwords never expire" sentinel (maxPwdAge == math.MinInt64). Two's
// complement has no positive representation for math.MinInt64, so negating
// it to compute a day count overflows and stays negative — silently making
// ANSSI_R1_PASSWORD_POLICY and WEAK_PASSWORD_POLICY declare the worst
// possible password policy (passwords that never expire) conformant
// (T_132/D5). Any sufficiently large day count defeats every "max age must
// be under N days" threshold in those detectors; this one also fits an
// int32 comfortably in the rendered JSON report.
const maxPwdAgeNeverExpiresDays = 999999

// filetimeMaxPwdAgeToDays converts the domain's maxPwdAge attribute — a
// negative FILETIME interval in 100-nanosecond units — to whole days,
// special-casing the sentinel that would otherwise overflow int64.
func filetimeMaxPwdAgeToDays(maxPwdAge int64) int {
	if maxPwdAge == math.MinInt64 {
		return maxPwdAgeNeverExpiresDays
	}
	return int(-maxPwdAge / (10000000 * 86400))
}

// GetDomainInfo retrieves domain-level information
func (c *Client) GetDomainInfo(ctx context.Context) (*types.DomainInfo, error) {
	if c.domainInfo != nil {
		return c.domainInfo, nil
	}

	// Get domain info from RootDSE and domain object
	info := &types.DomainInfo{
		DomainDN: c.config.BaseDN,
	}

	// Query RootDSE for naming contexts
	rootDSE, err := c.search(ctx, "", "(objectClass=*)", []string{
		"defaultNamingContext",
		"rootDomainNamingContext",
		"configurationNamingContext",
		"schemaNamingContext",
		"dnsHostName",
		"forestFunctionality",
	}, 1)
	var configDN string
	var schemaDN string
	if err == nil && len(rootDSE) > 0 {
		entry := rootDSE[0]
		if dn := entry.GetAttributeValue("defaultNamingContext"); dn != "" {
			info.DomainDN = dn
		}
		configDN = entry.GetAttributeValue("configurationNamingContext")
		schemaDN = entry.GetAttributeValue("schemaNamingContext")

		// Forest info
		rootDomainDN := entry.GetAttributeValue("rootDomainNamingContext")
		if rootDomainDN != "" {
			info.ForestName = dnToDomain(rootDomainDN)
			info.ForestFQDN = dnToDomain(rootDomainDN)
		}
		if fl := entry.GetAttributeValue("forestFunctionality"); fl != "" {
			level, _ := strconv.Atoi(fl)
			info.ForestFunctionalLevel = functionalLevelToString(level)
			info.ForestFunctionalLevelInt = level
		}
	}
	if configDN == "" {
		configDN = "CN=Configuration," + c.config.BaseDN
	}
	if schemaDN == "" {
		schemaDN = "CN=Schema," + configDN
	}
	// Fallback: if forest info is empty (single-domain forest or rootDSE incomplete)
	if info.ForestName == "" && info.DomainDN != "" {
		info.ForestName = dnToDomain(info.DomainDN)
		info.ForestFQDN = info.ForestName
	}

	// Query domain object for more details
	domainFilter := "(objectClass=domain)"
	domainEntries, err := c.search(ctx, c.config.BaseDN, domainFilter, []string{
		"objectSid",
		"name",
		"msDS-Behavior-Version",
		"minPwdLength",
		"pwdHistoryLength",
		"maxPwdAge",
		"minPwdAge",
		"lockoutThreshold",
		"lockoutDuration",
		"ms-DS-MachineAccountQuota",
		"whenCreated",
	}, 1)

	if err == nil && len(domainEntries) > 0 {
		entry := domainEntries[0]
		info.DomainSID = decodeSID(entry.GetRawAttributeValue("objectSid"))
		info.DomainName = entry.GetAttributeValue("name")
		info.MinPasswordLength = getIntAttr(entry, "minPwdLength")
		info.MinPwdLength = info.MinPasswordLength // Alias
		info.PasswordHistoryLength = getIntAttr(entry, "pwdHistoryLength")
		info.PwdHistoryLength = info.PasswordHistoryLength // Alias
		info.LockoutThreshold = getIntAttr(entry, "lockoutThreshold")
		info.MachineAccountQuota = getIntAttr(entry, "ms-DS-MachineAccountQuota")

		// Functional level
		level := getIntAttr(entry, "msDS-Behavior-Version")
		info.FunctionalLevel = functionalLevelToString(level)
		info.FunctionalLevelInt = level

		// Domain creation date
		info.DomainCreated = parseADTime(entry.GetAttributeValue("whenCreated"))

		// MaxPasswordAge (negative FILETIME interval in 100-nanosecond units → days)
		if maxPwdAgeStr := entry.GetAttributeValue("maxPwdAge"); maxPwdAgeStr != "" {
			if maxPwdAge, err := strconv.ParseInt(maxPwdAgeStr, 10, 64); err == nil && maxPwdAge < 0 {
				days := filetimeMaxPwdAgeToDays(maxPwdAge)
				info.MaxPasswordAge = days
				info.MaxPwdAge = days
			}
		}

		// MinPwdAge (negative FILETIME interval → days)
		if minPwdAgeStr := entry.GetAttributeValue("minPwdAge"); minPwdAgeStr != "" {
			if minPwdAge, err := strconv.ParseInt(minPwdAgeStr, 10, 64); err == nil && minPwdAge < 0 {
				info.MinPwdAge = int(-minPwdAge / (10000000 * 86400))
			}
		}

		// LockoutDuration (negative FILETIME interval → minutes)
		if lockoutDurStr := entry.GetAttributeValue("lockoutDuration"); lockoutDurStr != "" {
			if lockoutDur, err := strconv.ParseInt(lockoutDurStr, 10, 64); err == nil && lockoutDur < 0 {
				info.LockoutDuration = int(-lockoutDur / (10000000 * 60))
			}
		}
	}

	// Get domain controllers (include cn as fallback for DCs without dNSHostName)
	dcFilter := "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
	dcEntries, err := c.search(ctx, c.config.BaseDN, dcFilter, []string{"dNSHostName", "cn"}, 0)
	if err == nil {
		for _, entry := range dcEntries {
			dns := entry.GetAttributeValue("dNSHostName")
			if dns == "" {
				// Fallback: construct FQDN from cn + domain FQDN
				cn := entry.GetAttributeValue("cn")
				if cn != "" {
					domainFQDN := dnToDomain(c.config.BaseDN)
					if domainFQDN != "" {
						dns = cn + "." + domainFQDN
					} else {
						dns = cn
					}
				}
			}
			if dns != "" {
				info.DomainControllers = append(info.DomainControllers, dns)
			}
		}
	}

	// === Additional LDAP queries for DomainInfo fields ===

	// 1. Foreign Security Principals count
	fspDN := "CN=ForeignSecurityPrincipals," + c.config.BaseDN
	fspEntries, err := c.search(ctx, fspDN, "(objectClass=foreignSecurityPrincipal)", []string{"distinguishedName"}, 0)
	if err == nil {
		info.ForeignSecurityPrincipalsCount = len(fspEntries)
	}

	// 2. Recycle Bin enabled (check Optional Features)
	partitionsDN := "CN=Partitions," + configDN
	partEntries, err := c.search(ctx, partitionsDN, "(objectClass=*)", []string{"msDS-EnabledFeature"}, 1)
	if err == nil && len(partEntries) > 0 {
		features := partEntries[0].GetAttributeValues("msDS-EnabledFeature")
		for _, feature := range features {
			if strings.Contains(feature, "Recycle Bin Feature") {
				info.RecycleBinEnabled = true
				break
			}
		}
	}

	// 3. dsHeuristics (for anonymous LDAP, list object mode, etc.)
	dsDN := "CN=Directory Service,CN=Windows NT,CN=Services," + configDN
	dsEntries, err := c.search(ctx, dsDN, "(objectClass=*)", []string{"dSHeuristics"}, 1)
	if err == nil && len(dsEntries) > 0 {
		info.DsHeuristics = dsEntries[0].GetAttributeValue("dSHeuristics")
		// Anonymous LDAP allowed: 7th character of dSHeuristics == '2'
		if len(info.DsHeuristics) >= 7 && info.DsHeuristics[6] == '2' {
			info.AnonymousLDAPAllowed = true
		}
	}

	// 4. Schema version (objectVersion from CN=Schema,CN=Configuration)
	schemaEntries, err := c.search(ctx, schemaDN, "(objectClass=*)", []string{"objectVersion"}, 1)
	if err == nil && len(schemaEntries) > 0 {
		info.SchemaVersion = getIntAttr(schemaEntries[0], "objectVersion")
	}

	// 5. NetBIOS name (nETBIOSName from crossRef partition matching our domain)
	partFilter := crossRefFilter(c.config.BaseDN)
	nbEntries, err := c.search(ctx, partitionsDN, partFilter, []string{"nETBIOSName"}, 1)
	if err == nil && len(nbEntries) > 0 {
		info.NetBIOSName = nbEntries[0].GetAttributeValue("nETBIOSName")
	}

	// 6. KRBTGT account info (password last set + key version)
	krbtgtFilter := "(&(objectClass=user)(sAMAccountName=krbtgt))"
	krbtgtEntries, err := c.search(ctx, c.config.BaseDN, krbtgtFilter,
		[]string{"pwdLastSet", "msDS-KeyVersionNumber"}, 1)
	if err == nil && len(krbtgtEntries) > 0 {
		info.KrbtgtPasswordLastSet = parseFileTime(krbtgtEntries[0].GetAttributeValue("pwdLastSet"))
		info.KrbtgtKeyVersion = getIntAttr(krbtgtEntries[0], "msDS-KeyVersionNumber")
	}

	// 7. Last AD backup date (heuristic: latest whenChanged on NTDS Settings objects)
	sitesDN := "CN=Sites," + configDN
	ntdsFilter := "(objectClass=nTDSDSA)"
	ntdsEntries, err := c.search(ctx, sitesDN, ntdsFilter, []string{"whenChanged"}, 0)
	if err == nil && len(ntdsEntries) > 0 {
		var latestBackup time.Time
		for _, entry := range ntdsEntries {
			wc := parseADTime(entry.GetAttributeValue("whenChanged"))
			if !wc.IsZero() && wc.After(latestBackup) {
				latestBackup = wc
			}
		}
		if !latestBackup.IsZero() {
			info.LastADBackupDate = &latestBackup
		}
	}

	// 8. KDS root key provisioned (gMSA prerequisite)
	kdsDN := "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services," + configDN
	kdsEntries, err := c.search(ctx, kdsDN, "(objectClass=msKds-ProvRootKey)", []string{"cn"}, 1)
	if err == nil && len(kdsEntries) > 0 {
		info.HasKdsRootKey = true
	}

	// 9. Disabled users count
	disabledFilter := "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))"
	disabledEntries, err := c.search(ctx, c.config.BaseDN, disabledFilter, []string{"cn"}, 0)
	if err == nil {
		info.DisabledUsersCount = len(disabledEntries)
	}

	// 10. DC count
	info.DCCount = len(info.DomainControllers)

	// 11. Guest account status
	guestFilter := "(&(objectClass=user)(sAMAccountName=Guest))"
	guestEntries, err := c.search(ctx, c.config.BaseDN, guestFilter, []string{"userAccountControl"}, 1)
	if err == nil && len(guestEntries) > 0 {
		uac := getIntAttr(guestEntries[0], "userAccountControl")
		info.GuestEnabled = (uac & 0x2) == 0 // ACCOUNTDISABLE bit NOT set = enabled
	}

	// 12. Built-in Administrator account info (last login, name), resolved by
	// the well-known RID-500 SID (<domainSID>-500) rather than by name — a
	// renamed built-in admin account is exactly the case M12_DEFAULT_ADMIN_
	// NOT_RENAMED must be able to see (T_127; T_124 had flagged the previous
	// name-based lookup as a latent false-negative risk).
	if sidFilter := encodeSIDFilter(info.DomainSID, 500); sidFilter != "" {
		adminFilter := fmt.Sprintf("(&(objectClass=user)(objectSid=%s))", sidFilter)
		adminEntries, err := c.search(ctx, c.config.BaseDN, adminFilter,
			[]string{"lastLogonTimestamp", "sAMAccountName"}, 1)
		if err == nil && len(adminEntries) > 0 {
			info.AdminAccountName = adminEntries[0].GetAttributeValue("sAMAccountName")
			info.AdminLastLoginDate = parseFileTime(adminEntries[0].GetAttributeValue("lastLogonTimestamp"))
		}
	}

	// 13. Exchange schema version (rangeUpper on ms-Exch-Schema-Version-Pt)
	exchFilter := "(cn=ms-Exch-Schema-Version-Pt)"
	exchEntries, err := c.search(ctx, schemaDN, exchFilter, []string{"rangeUpper"}, 1)
	if err == nil && len(exchEntries) > 0 {
		info.ExchangeSchemaVersion = getIntAttr(exchEntries[0], "rangeUpper")
	}

	// 14. SYSVOL replication: NTFRS vs DFSR
	// Check if NTFRS subscription exists for any DC
	ntfrsFilter := "(&(objectClass=nTFRSSubscriber)(name=Domain System Volume (SYSVOL share)))"
	ntfrsEntries, err := c.search(ctx, c.config.BaseDN, ntfrsFilter, []string{"cn"}, 1)
	if err == nil && len(ntfrsEntries) > 0 {
		info.UsingNTFRSForSYSVOL = true
	}

	// 15. LAPS schema detection (legacy ms-Mcs-AdmPwd and new msLAPS-Password)
	lapsFilter := "(cn=ms-Mcs-AdmPwd)"
	lapsEntries, err := c.search(ctx, schemaDN, lapsFilter, []string{"cn"}, 1)
	if err == nil && len(lapsEntries) > 0 {
		info.LAPSSchemaInstalled = true
	}
	newLapsFilter := "(cn=msLAPS-Password)"
	newLapsEntries, err := c.search(ctx, schemaDN, newLapsFilter, []string{"cn"}, 1)
	if err == nil && len(newLapsEntries) > 0 {
		info.NewLAPSSchemaInstalled = true
	}

	// 16. Pre-Windows 2000 Compatible Access group: check for Authenticated Users (S-1-5-11)
	preWin2000Filter := "(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))"
	preWin2000Entries, err := c.search(ctx, c.config.BaseDN, preWin2000Filter, []string{"member"}, 1)
	if err == nil && len(preWin2000Entries) > 0 {
		members := preWin2000Entries[0].GetAttributeValues("member")
		for _, m := range members {
			// Authenticated Users is a well-known SID, may appear as FSP
			if strings.Contains(strings.ToUpper(m), "S-1-5-11") {
				info.PreWin2000AuthenticatedUsers = true
				break
			}
		}
	}
	// Also check primaryGroupToken approach: S-1-5-11 might be in the group via nested membership
	// Check if the well-known SID foreign security principal exists
	if !info.PreWin2000AuthenticatedUsers {
		fspFilter := "(cn=S-1-5-11)"
		fspDN2 := "CN=ForeignSecurityPrincipals," + c.config.BaseDN
		fspEntries2, err := c.search(ctx, fspDN2, fspFilter, []string{"memberOf"}, 1)
		if err == nil && len(fspEntries2) > 0 {
			memberOf := fspEntries2[0].GetAttributeValues("memberOf")
			for _, g := range memberOf {
				if strings.Contains(g, "Pre-Windows 2000 Compatible Access") {
					info.PreWin2000AuthenticatedUsers = true
					break
				}
			}
		}
	}

	// 17. Sites & Subnets count
	siteEntries, err := c.search(ctx, sitesDN, "(objectClass=site)", []string{"cn"}, 0)
	if err == nil {
		info.SitesCount = len(siteEntries)
	}
	subnetsDN := "CN=Subnets," + sitesDN
	subnetEntries, err := c.search(ctx, subnetsDN, "(objectClass=subnet)", []string{"cn"}, 0)
	if err == nil {
		info.SubnetsCount = len(subnetEntries)
	}

	// 18. ForestFunctionalLevel fallback (use domain level if forest level empty)
	if info.ForestFunctionalLevel == "" && info.FunctionalLevel != "" {
		info.ForestFunctionalLevel = info.FunctionalLevel
		info.ForestFunctionalLevelInt = info.FunctionalLevelInt
	}

	c.domainInfo = info
	return info, nil
}

// dnToDomain converts a DN like "DC=example,DC=com" to "example.com"
func dnToDomain(dn string) string {
	parts := strings.Split(dn, ",")
	var domainParts []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			domainParts = append(domainParts, part[3:])
		}
	}
	return strings.Join(domainParts, ".")
}

// GetOUs retrieves Organizational Units
func (c *Client) GetOUs(ctx context.Context, opts providers.QueryOptions) ([]types.OU, error) {
	filter := "(objectClass=organizationalUnit)"
	attrs := []string{
		"distinguishedName",
		"name",
		"description",
		"whenCreated",
		"whenChanged",
		"gPLink",
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, 0)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get ous", err)
	}

	ous := make([]types.OU, 0, len(entries))
	for _, entry := range entries {
		ou := types.OU{
			DN:                entry.DN,
			DistinguishedName: entry.DN,
			Name:              entry.GetAttributeValue("name"),
			Description:       entry.GetAttributeValue("description"),
			Created:           parseADTime(entry.GetAttributeValue("whenCreated")),
			Modified:          parseADTime(entry.GetAttributeValue("whenChanged")),
		}

		// Extract GPO links if present
		gpoLink := entry.GetAttributeValue("gPLink")
		if gpoLink != "" {
			ou.GPOLinks = parseGPOLinks(gpoLink)
		}

		ous = append(ous, ou)
	}

	return ous, nil
}

// parseGPOLinks extracts GPO GUIDs from gPLink attribute
// Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;0][LDAP://...;1]
func parseGPOLinks(gpoLink string) []string {
	var links []string
	// Simple extraction of GUIDs between {} brackets
	for i := 0; i < len(gpoLink); i++ {
		if gpoLink[i] == '{' {
			end := i + 1
			for end < len(gpoLink) && gpoLink[end] != '}' {
				end++
			}
			if end < len(gpoLink) {
				guid := gpoLink[i : end+1]
				links = append(links, guid)
				i = end
			}
		}
	}
	return links
}

// GetGPOs retrieves Group Policy Objects
func (c *Client) GetGPOs(ctx context.Context, opts providers.QueryOptions) ([]types.GPO, error) {
	filter := "(objectClass=groupPolicyContainer)"
	attrs := []string{
		"distinguishedName",
		"displayName",
		"name",
		"gPCFileSysPath",
		"flags",
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, 0)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get gpos", err)
	}

	gpos := make([]types.GPO, 0, len(entries))
	for _, entry := range entries {
		name := entry.GetAttributeValue("name")
		gpo := types.GPO{
			DN:                entry.DN,
			DistinguishedName: entry.DN, // Alias
			CN:                name,     // Common name (GUID format: {xxx-xxx-xxx})
			Name:              name,
			DisplayName:       entry.GetAttributeValue("displayName"),
			GUID:              name,
			FilePath:          entry.GetAttributeValue("gPCFileSysPath"),
		}

		flags := getIntAttr(entry, "flags")
		gpo.Flags = flags
		gpo.UserEnabled = (flags & 1) == 0
		gpo.ComputerEnabled = (flags & 2) == 0
		gpo.Enabled = gpo.UserEnabled || gpo.ComputerEnabled

		gpos = append(gpos, gpo)
	}

	return gpos, nil
}

// GetGPOLinks retrieves GPO links from OUs, Sites, and Domain
func (c *Client) GetGPOLinks(ctx context.Context) ([]audit.GPOLink, error) {
	// Search for objects that can have GPO links (OUs, Sites, Domain)
	filter := "(|(objectClass=organizationalUnit)(objectClass=domainDNS)(objectClass=site))"
	attrs := []string{
		"distinguishedName",
		"gPLink",
		"gPOptions",
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, 0)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get gpo links", err)
	}

	// Also search in Configuration partition for Sites
	configDN := "CN=Sites,CN=Configuration," + c.config.BaseDN
	siteEntries, _ := c.search(ctx, configDN, "(objectClass=site)", attrs, 0)
	entries = append(entries, siteEntries...)

	var links []audit.GPOLink
	for _, entry := range entries {
		gpLink := entry.GetAttributeValue("gPLink")
		if gpLink == "" {
			continue
		}

		// Parse gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;flags][...]
		parsedLinks := parseGPLinks(gpLink, entry.DN)
		links = append(links, parsedLinks...)
	}

	return links, nil
}

// parseGPLinks parses the gPLink attribute format
// Format: [LDAP://CN={GUID},CN=Policies,CN=System,DC=...;flags]
// Flags: 0=enabled, 1=disabled, 2=enforced
func parseGPLinks(gpLink string, linkedTo string) []audit.GPOLink {
	var links []audit.GPOLink
	order := 0

	// Split by ][ to get individual links
	for len(gpLink) > 0 {
		start := strings.Index(gpLink, "[LDAP://")
		if start == -1 {
			break
		}
		end := strings.Index(gpLink[start:], "]")
		if end == -1 {
			break
		}
		end += start

		linkStr := gpLink[start+8 : end] // Skip "[LDAP://"
		gpLink = gpLink[end+1:]

		// Split by semicolon: DN;flags
		parts := strings.SplitN(linkStr, ";", 2)
		if len(parts) != 2 {
			continue
		}

		gpoDN := parts[0]
		flags, _ := strconv.Atoi(parts[1])

		// Extract CN (GUID with braces) from DN (CN={GUID},CN=Policies,...)
		gpoCN := ""
		gpoGuid := ""
		if idx := strings.Index(strings.ToUpper(gpoDN), "CN={"); idx != -1 {
			endIdx := strings.Index(gpoDN[idx+3:], ",")
			if endIdx != -1 {
				gpoCN = gpoDN[idx+3 : idx+3+endIdx] // Extract {GUID}
				gpoGuid = strings.Trim(gpoCN, "{}") // GUID without braces
			}
		}

		link := audit.GPOLink{
			GPOCN:       gpoCN, // CN = {GUID}
			GPOGuid:     gpoGuid,
			LinkedTo:    linkedTo,
			LinkEnabled: (flags & 1) == 0,
			Disabled:    (flags & 1) != 0,
			Enforced:    (flags & 2) != 0,
			Order:       order,
		}
		links = append(links, link)
		order++
	}

	return links
}

// GetGPOAcls retrieves ACLs on GPO objects
func (c *Client) GetGPOAcls(ctx context.Context, gpoDNs []string) ([]audit.GPOAcl, error) {
	if len(gpoDNs) == 0 {
		return nil, nil
	}

	// Get security descriptors for GPOs
	acls, _, err := c.GetACLs(ctx, gpoDNs)
	if err != nil {
		return nil, err
	}

	// Convert ACLEntries to GPOAcl format
	var gpoAcls []audit.GPOAcl
	for _, acl := range acls {
		gpoAcl := audit.GPOAcl{
			GPODN:      acl.ObjectDN,
			Trustee:    acl.Trustee,
			TrusteeSID: acl.Trustee, // Trustee contains SID
			AccessMask: acl.AccessMask,
			AceType:    acl.AceType,
		}
		gpoAcls = append(gpoAcls, gpoAcl)
	}

	return gpoAcls, nil
}

// GetTrusts retrieves domain trusts
func (c *Client) GetTrusts(ctx context.Context, opts providers.QueryOptions) ([]types.Trust, error) {
	filter := "(objectClass=trustedDomain)"
	attrs := []string{
		"distinguishedName",
		"name",
		"trustDirection",
		"trustType",
		"trustAttributes",
		"pwdLastSet",  // v3.1.18 — ANSSI R42 (real rotation timestamp)
		"whenCreated", // v3.1.18 — fallback when pwdLastSet unreadable
	}

	entries, err := c.search(ctx, c.config.BaseDN, filter, attrs, 0)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get trusts", err)
	}

	trusts := make([]types.Trust, 0, len(entries))
	for _, entry := range entries {
		trust := types.Trust{
			TargetDomain:    entry.GetAttributeValue("name"),
			WhenCreated:     entry.GetAttributeValue("whenCreated"),
			PasswordLastSet: parseFileTime(entry.GetAttributeValue("pwdLastSet")),
		}

		// Parse trust direction
		direction := getIntAttr(entry, "trustDirection")
		switch direction {
		case 1:
			trust.TrustDirection = "Inbound"
		case 2:
			trust.TrustDirection = "Outbound"
		case 3:
			trust.TrustDirection = "Bidirectional"
		}

		// Parse trust type
		trustType := getIntAttr(entry, "trustType")
		switch trustType {
		case 1:
			trust.TrustType = "Downlevel"
		case 2:
			trust.TrustType = "Uplevel"
		case 3:
			trust.TrustType = "MIT"
		case 4:
			trust.TrustType = "DCE"
		}

		// Trust attributes
		attrs := getIntAttr(entry, "trustAttributes")
		trust.SIDFiltering = (attrs & 4) != 0
		trust.SelectiveAuth = (attrs & 16) != 0

		trusts = append(trusts, trust)
	}

	return trusts, nil
}

// GetCertAuthorities enumerates Enterprise CAs from CN=Enrollment Services
// in the Configuration partition. Returns (nil, nil) when the container
// isn't accessible (LDAP perm denied, no ADCS deployed) — caller treats
// this as "no CA data available" and skips R36 detector silently.
//
// v3.1.19 — added for ANSSI PA-099 R36 (CA risks affecting Tier 0).
func (c *Client) GetCertAuthorities(ctx context.Context) ([]types.CertAuthority, error) {
	configDN := "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + c.config.BaseDN
	filter := "(objectClass=pKIEnrollmentService)"
	attrs := []string{
		"distinguishedName",
		"name",
		"dNSHostName",
		"cACertificate",
		"certificateTemplates",
	}
	entries, err := c.search(ctx, configDN, filter, attrs, 0)
	if err != nil {
		// Container may not be accessible (no ADCS, RODC perm denied).
		// Returning nil avoids false negatives — R36 detector skips.
		return nil, nil
	}

	cas := make([]types.CertAuthority, 0, len(entries))
	for _, entry := range entries {
		ca := types.CertAuthority{
			DN:                 entry.DN,
			Name:               entry.GetAttributeValue("name"),
			DNSHostName:        entry.GetAttributeValue("dNSHostName"),
			PublishedTemplates: entry.GetAttributeValues("certificateTemplates"),
		}
		// Parse the cACertificate (DER-encoded X.509) for signing alg + expiry.
		if rawCert := entry.GetRawAttributeValue("cACertificate"); len(rawCert) > 0 {
			if cert, err := x509.ParseCertificate(rawCert); err == nil {
				sum := sha1.Sum(cert.Raw)
				ca.CACertSHA1 = hex.EncodeToString(sum[:])
				ca.CACertNotAfter = cert.NotAfter
				ca.CACertSigAlg = cert.SignatureAlgorithm.String()
			}
		}
		cas = append(cas, ca)
	}
	return cas, nil
}

// GetCertTemplates retrieves certificate templates
func (c *Client) GetCertTemplates(ctx context.Context, opts providers.QueryOptions) ([]types.CertTemplate, error) {
	// Certificate templates are in the Configuration partition
	configDN := "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + c.config.BaseDN

	filter := "(objectClass=pKICertificateTemplate)"
	attrs := []string{
		"distinguishedName",
		"name",
		"displayName",
		"msPKI-Cert-Template-OID",
		"msPKI-Enrollment-Flag",
		"msPKI-RA-Signature",
		"pKIExtendedKeyUsage",
		"msPKI-Certificate-Name-Flag",
		"msPKI-Template-Schema-Version",
		"pKIExpirationPeriod",
		"pKIOverlapPeriod",
		"msPKI-Minimal-Key-Size", // v3.1.18 — ANSSI R37 key strength
	}

	entries, err := c.search(ctx, configDN, filter, attrs, 0)
	if err != nil {
		// May not have access to Configuration partition
		return nil, nil
	}

	templates := make([]types.CertTemplate, 0, len(entries))
	for _, entry := range entries {
		template := types.CertTemplate{
			DN:                   entry.DN,
			Name:                 entry.GetAttributeValue("name"),
			DisplayName:          entry.GetAttributeValue("displayName"),
			OID:                  entry.GetAttributeValue("msPKI-Cert-Template-OID"),
			EnrollmentFlag:       getIntAttr(entry, "msPKI-Enrollment-Flag"),
			AuthorizedSignatures: getIntAttr(entry, "msPKI-RA-Signature"),
			SubjectNameFlag:      getIntAttr(entry, "msPKI-Certificate-Name-Flag"),
			CertificateNameFlag:  getIntAttr(entry, "msPKI-Certificate-Name-Flag"),
			SchemaVersion:        getIntAttr(entry, "msPKI-Template-Schema-Version"),
			ExtendedKeyUsage:     entry.GetAttributeValues("pKIExtendedKeyUsage"),
			ValidityPeriod:       decodeFiletimeDuration(entry.GetRawAttributeValue("pKIExpirationPeriod")),
			RenewalPeriod:        decodeFiletimeDuration(entry.GetRawAttributeValue("pKIOverlapPeriod")),
			MinKeyLength:         getIntAttr(entry, "msPKI-Minimal-Key-Size"), // v3.1.18 — ANSSI R37
		}

		// Check if manager approval required
		template.RequiresManagerApproval = (template.EnrollmentFlag & 2) != 0

		templates = append(templates, template)
	}

	return templates, nil
}

// GetObjectACL retrieves the ACL for a specific object
func (c *Client) GetObjectACL(ctx context.Context, dn string) ([]types.ACE, error) {
	entries, _, err := c.getSecurityDescriptors(ctx, []string{dn})
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeLDAP, "get acl", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("object not found: %s", dn)
	}

	// Convert ACLEntry to ACE
	var aces []types.ACE
	for _, entry := range entries {
		aces = append(aces, types.ACE{
			PrincipalSID: entry.Trustee,
			AccessMask:   entry.AccessMask,
			AceType:      entry.AceType,
			ObjectType:   entry.ObjectType,
		})
	}
	return aces, nil
}

// GetDCMetadata collects per-DC enrichment fields (FSMO roles, site name,
// replication partners, RODC flag) needed by the v3.1.29 INFO_DOMAIN_CONTROLLER
// detector. Returns a map keyed by DC computer-DN.
//
// Strategy:
//  1. Query the 5 FSMO holder objects, each carries fSMORoleOwner pointing to
//     a NTDS Settings DN. The DC's computer DN is the parent of the parent
//     of NTDS Settings (CN=NTDS Settings,CN=<DC>,CN=Servers,CN=<Site>,...).
//  2. Walk every nTDSDSA under CN=Sites,CN=Configuration to enumerate DCs and
//     extract their site (4th RDN of the NTDS Settings DN). Their replication
//     partners are the fromServer attribute of nTDSConnection child objects.
func (c *Client) GetDCMetadata(ctx context.Context, dcs []types.Computer) (map[string]*audit.DCMetadata, error) {
	out := make(map[string]*audit.DCMetadata, len(dcs))
	if len(dcs) == 0 {
		return out, nil
	}
	configDN := "CN=Configuration," + c.config.BaseDN
	sitesDN := "CN=Sites," + configDN

	// Pre-build {dnsHostName → computerDN} index from the typed Computer slice.
	dcByHost := make(map[string]string, len(dcs))
	dcByCN := make(map[string]string, len(dcs))
	for _, d := range dcs {
		out[d.DN] = &audit.DCMetadata{
			FSMORoles:           []string{},
			ReplicationPartners: []string{},
			IsRODC:              (d.UserAccountControl & UAC_PARTIAL_SECRETS_ACCOUNT) != 0,
		}
		if d.DNSHostName != "" {
			dcByHost[strings.ToLower(d.DNSHostName)] = d.DN
		}
		if cn := dnFirstCN(d.DN); cn != "" {
			dcByCN[strings.ToLower(cn)] = d.DN
		}
	}

	// 1. FSMO roles — base searches on the 5 known holders.
	fsmoHolders := []struct {
		dn   string
		role string
	}{
		{c.config.BaseDN, "PDCEmulator"},
		{"CN=Schema," + configDN, "SchemaMaster"},
		{"CN=Partitions," + configDN, "DomainNamingMaster"},
		{"CN=RID Manager$,CN=System," + c.config.BaseDN, "RIDMaster"},
		{"CN=Infrastructure," + c.config.BaseDN, "InfrastructureMaster"},
	}
	for _, h := range fsmoHolders {
		entries, err := c.search(ctx, h.dn, "(objectClass=*)", []string{"fSMORoleOwner"}, 1)
		if err != nil || len(entries) == 0 {
			continue
		}
		ntdsDN := entries[0].GetAttributeValue("fSMORoleOwner")
		dcDN := ntdsToDcDN(ntdsDN, dcByCN)
		if dcDN == "" {
			continue
		}
		if meta := out[dcDN]; meta != nil {
			meta.FSMORoles = append(meta.FSMORoles, h.role)
		}
	}

	// 2. Sites + replication partners — enumerate nTDSDSA across all sites.
	ntdsEntries, err := c.search(ctx, sitesDN, "(objectClass=nTDSDSA)", []string{"distinguishedName"}, 0)
	if err == nil {
		for _, ntds := range ntdsEntries {
			dcDN := ntdsToDcDN(ntds.DN, dcByCN)
			if dcDN == "" {
				continue
			}
			meta := out[dcDN]
			if meta == nil {
				continue
			}
			meta.Site = ntdsToSite(ntds.DN)

			// Replication partners: nTDSConnection children → fromServer points to a NTDS Settings DN.
			connEntries, _ := c.search(ctx, ntds.DN, "(objectClass=nTDSConnection)", []string{"fromServer"}, 0)
			for _, conn := range connEntries {
				if from := conn.GetAttributeValue("fromServer"); from != "" {
					if peerDN := ntdsToDcDN(from, dcByCN); peerDN != "" && peerDN != dcDN {
						meta.ReplicationPartners = append(meta.ReplicationPartners, peerDN)
					}
				}
			}
		}
	}
	return out, nil
}

// dnFirstCN returns the first CN= value of a DN (the leaf RDN), lowercased.
// Returns "" when the DN has no CN segment.
func dnFirstCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(p), "cn=") {
			return p[3:]
		}
	}
	return ""
}

// ntdsToDcDN turns a NTDS Settings DN (CN=NTDS Settings,CN=<DC>,CN=Servers,...)
// into the corresponding DC computer DN by looking up <DC> in the dcByCN map.
// Returns "" when no match.
func ntdsToDcDN(ntdsDN string, dcByCN map[string]string) string {
	if ntdsDN == "" {
		return ""
	}
	parts := strings.Split(ntdsDN, ",")
	if len(parts) < 2 {
		return ""
	}
	// Second RDN is CN=<DC name>
	dcRDN := strings.TrimSpace(parts[1])
	if !strings.HasPrefix(strings.ToLower(dcRDN), "cn=") {
		return ""
	}
	return dcByCN[strings.ToLower(dcRDN[3:])]
}

// ntdsToSite parses CN=NTDS Settings,CN=<DC>,CN=Servers,CN=<Site>,CN=Sites,...
// and returns <Site>. Returns "" when the DN doesn't fit the canonical shape.
func ntdsToSite(ntdsDN string) string {
	parts := strings.Split(ntdsDN, ",")
	if len(parts) < 4 {
		return ""
	}
	siteRDN := strings.TrimSpace(parts[3])
	if !strings.HasPrefix(strings.ToLower(siteRDN), "cn=") {
		return ""
	}
	return siteRDN[3:]
}

// LookupBatch resolves a batch of arbitrary DNs to a minimal attribute set
// (objectClass, sAMAccountName, cn). Used by the audit engine to fill in
// ObjectByDN entries for ACL targets that aren't part of the typed
// collections (containers, schema objects, AdminSDHolder, …) so detectors
// can emit a typed AffectedEntity instead of bare {type: "object", dn: …}.
//
// Batches DNs into OR-filter chunks under the AD filter-length limit
// (~10 KB). Per-DN failures (deleted object, ACL denies read) are silently
// skipped — the engine falls back to EntityTypePrincipal for the misses.
func (c *Client) LookupBatch(ctx context.Context, dns []string) ([]audit.ObjectLookupEntry, error) {
	if len(dns) == 0 {
		return nil, nil
	}
	attrs := []string{"distinguishedName", "objectClass", "sAMAccountName", "cn", "objectSid"}
	const chunkSize = 50
	var out []audit.ObjectLookupEntry
	for i := 0; i < len(dns); i += chunkSize {
		end := i + chunkSize
		if end > len(dns) {
			end = len(dns)
		}
		var b strings.Builder
		b.WriteString("(|")
		for _, dn := range dns[i:end] {
			b.WriteString("(distinguishedName=")
			b.WriteString(ldap.EscapeFilter(dn))
			b.WriteString(")")
		}
		b.WriteString(")")

		entries, err := c.search(ctx, c.config.BaseDN, b.String(), attrs, 0)
		if err != nil {
			// Don't abort the whole audit on a single chunk failure — log and
			// continue. Misses fall back to EntityTypePrincipal in the cache.
			continue
		}
		for _, e := range entries {
			out = append(out, audit.ObjectLookupEntry{
				DN:             e.DN,
				CN:             e.GetAttributeValue("cn"),
				SAMAccountName: e.GetAttributeValue("sAMAccountName"),
				ObjectClass:    e.GetAttributeValues("objectClass"),
				SID:            decodeSID(e.GetRawAttributeValue("objectSid")),
			})
		}
	}
	return out, nil
}

// GetACLs retrieves ACLs and object ownership for multiple objects (users, groups, computers, etc.)
// Returns ACL entries (DACL ACEs) and a map of objectDN → ownerSID.
// This is the bulk ACL collection method used by the audit engine.
func (c *Client) GetACLs(ctx context.Context, objectDNs []string) ([]types.ACLEntry, map[string]string, error) {
	if len(objectDNs) == 0 {
		return nil, nil, nil
	}

	return c.getSecurityDescriptors(ctx, objectDNs)
}

// getSecurityDescriptors fetches and parses security descriptors for multiple DNs.
// Wraps doGetSecurityDescriptors with reconnect-on-network-error so an idle-closed
// TCP connection (DC idle timeout ~15-22 min) is transparently recovered before
// the audit aborts.
func (c *Client) getSecurityDescriptors(ctx context.Context, dns []string) ([]types.ACLEntry, map[string]string, error) {
	entries, owners, err := c.doGetSecurityDescriptors(ctx, dns)
	if err != nil && isNetworkError(err) {
		if reconnErr := c.Reconnect(ctx); reconnErr == nil {
			entries, owners, err = c.doGetSecurityDescriptors(ctx, dns)
		}
	}
	return entries, owners, err
}

// doGetSecurityDescriptors is the core implementation. Per-object errors
// (permission denied, object not found) are skipped, but a network-level error
// aborts the whole call so the wrapper can reconnect + retry.
// Uses LDAP_SERVER_SD_FLAGS_OID control (1.2.840.113556.1.4.801) with flags 0x07
// to request OWNER, GROUP, and DACL in the security descriptor.
func (c *Client) doGetSecurityDescriptors(ctx context.Context, dns []string) ([]types.ACLEntry, map[string]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.conn == nil {
		return nil, nil, fmt.Errorf("not connected")
	}

	var allEntries []types.ACLEntry
	owners := make(map[string]string)

	// LDAP_SERVER_SD_FLAGS_OID control
	// OID: 1.2.840.113556.1.4.801
	// Value: BER INTEGER encoding: 0x02 (INTEGER tag), 0x01 (length), 0x07 (value)
	// 0x07 = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	// critical: false (must match what ldapts uses)
	sdFlagsControl := ldap.NewControlString("1.2.840.113556.1.4.801", false, string([]byte{0x02, 0x01, 0x07}))

	// Process in batches of 100 to avoid overwhelming the server
	batchSize := 100
	for i := 0; i < len(dns); i += batchSize {
		end := i + batchSize
		if end > len(dns) {
			end = len(dns)
		}
		batch := dns[i:end]

		for _, dn := range batch {
			// Create search request for single object
			searchReq := ldap.NewSearchRequest(
				dn,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				1,
				int(c.config.Timeout.Seconds()),
				false,
				"(objectClass=*)",
				[]string{"nTSecurityDescriptor"},
				[]ldap.Control{sdFlagsControl},
			)

			result, err := c.conn.Search(searchReq)
			if err != nil {
				// Dead TCP connection — abort so the wrapper can reconnect + retry.
				if isNetworkError(err) {
					return nil, nil, err
				}
				// Per-object error (permission denied, not found, etc.) — skip.
				continue
			}

			for _, entry := range result.Entries {
				// Get raw binary security descriptor
				sdBytes := entry.GetRawAttributeValue("nTSecurityDescriptor")
				if len(sdBytes) == 0 {
					continue
				}

				// Parse DACL into ACL entries
				aclEntries := ParseSecurityDescriptor(sdBytes, dn)
				allEntries = append(allEntries, aclEntries...)

				// Extract Owner SID for Owns edges
				ownerSID := ParseOwnerSID(sdBytes)
				if ownerSID != "" {
					owners[dn] = ownerSID
				}
			}
		}
	}

	return allEntries, owners, nil
}

// GetDNSZones retrieves AD-integrated DNS zones via LDAP (DomainDnsZones + ForestDnsZones partitions)
func (c *Client) GetDNSZones(ctx context.Context) ([]types.DNSZone, error) {
	// Search both DomainDnsZones and ForestDnsZones partitions
	partitions := []string{
		"CN=MicrosoftDNS,DC=DomainDnsZones," + c.config.BaseDN,
		"CN=MicrosoftDNS,DC=ForestDnsZones," + c.config.BaseDN,
	}

	zoneFilter := "(objectClass=dnsZone)"
	zoneAttrs := []string{"name", "dNSProperty"}

	var zones []types.DNSZone
	for _, dnsBaseDN := range partitions {
		entries, err := c.search(ctx, dnsBaseDN, zoneFilter, zoneAttrs, 0)
		if err != nil {
			// Partition may not be accessible; continue to next
			continue
		}

		for _, entry := range entries {
			zoneName := entry.GetAttributeValue("name")
			if zoneName == "" || zoneName == "RootDNSServers" || zoneName == "..TrustAnchors" {
				continue
			}

			zone := types.DNSZone{
				DN:            entry.DN,
				Name:          zoneName,
				DynamicUpdate: "unknown",
			}

			// Parse dNSProperty binary blob to extract zone properties
			dnsProps := entry.GetRawAttributeValues("dNSProperty")
			for _, prop := range dnsProps {
				if len(prop) < 16 {
					continue
				}
				// dNSProperty structure: bytes 0-3 = DataLength, 4-7 = PropId
				propID := uint32(prop[4]) | uint32(prop[5])<<8 | uint32(prop[6])<<16 | uint32(prop[7])<<24

				switch propID {
				case 0x00000002: // DSPROPERTY_ZONE_ALLOW_UPDATE
					if len(prop) >= 20 {
						updateFlag := uint32(prop[16]) | uint32(prop[17])<<8
						switch updateFlag {
						case 0:
							zone.DynamicUpdate = "none"
						case 1:
							zone.DynamicUpdate = "nonsecure"
						case 2:
							zone.DynamicUpdate = "secure"
						}
					}
				case 0x00000010: // DSPROPERTY_ZONE_SECURE_TIME (DNSSEC indicator)
					zone.DNSSECEnabled = true
				}
			}

			// Search for wildcard records in this zone
			wildcardDN := "DC=" + zoneName + "," + dnsBaseDN
			wildcardFilter := "(&(objectClass=dnsNode)(dc=*))"
			wildcardEntries, err := c.search(ctx, wildcardDN, wildcardFilter, []string{"dc"}, 0)
			if err == nil {
				for _, we := range wildcardEntries {
					dc := we.GetAttributeValue("dc")
					if dc == "*" {
						zone.WildcardRecords = append(zone.WildcardRecords, dc+"."+zoneName)
					}
				}
			}

			zones = append(zones, zone)
		}
	}

	return zones, nil
}

// GetFGPPs retrieves Fine-Grained Password Policies (Password Settings Objects)
func (c *Client) GetFGPPs(ctx context.Context) ([]types.FGPP, error) {
	psoDN := "CN=Password Settings Container,CN=System," + c.config.BaseDN
	filter := "(objectClass=msDS-PasswordSettings)"
	attrs := []string{
		"distinguishedName",
		"name",
		"msDS-PasswordSettingsPrecedence",
		"msDS-MinimumPasswordLength",
		"msDS-PasswordHistoryLength",
		"msDS-LockoutThreshold",
		"msDS-PSOAppliesTo",
	}

	entries, err := c.search(ctx, psoDN, filter, attrs, 0)
	if err != nil {
		// Container may not exist or not accessible
		return nil, nil
	}

	fgpps := make([]types.FGPP, 0, len(entries))
	for _, entry := range entries {
		fgpp := types.FGPP{
			DN:                    entry.DN,
			Name:                  entry.GetAttributeValue("name"),
			Precedence:            getIntAttr(entry, "msDS-PasswordSettingsPrecedence"),
			MinPasswordLength:     getIntAttr(entry, "msDS-MinimumPasswordLength"),
			PasswordHistoryLength: getIntAttr(entry, "msDS-PasswordHistoryLength"),
			LockoutThreshold:      getIntAttr(entry, "msDS-LockoutThreshold"),
			AppliesTo:             entry.GetAttributeValues("msDS-PSOAppliesTo"),
		}
		fgpps = append(fgpps, fgpp)
	}

	return fgpps, nil
}

// GetSitesAndSubnets retrieves AD sites and subnets from the Configuration partition
func (c *Client) GetSitesAndSubnets(ctx context.Context) ([]audit.Site, []audit.Subnet, error) {
	configDN := "CN=Configuration," + c.config.BaseDN
	sitesDN := "CN=Sites," + configDN

	// Query Sites
	siteFilter := "(objectClass=site)"
	siteAttrs := []string{"name", "description"}
	siteEntries, err := c.search(ctx, sitesDN, siteFilter, siteAttrs, 0)
	if err != nil {
		return nil, nil, err
	}

	var sites []audit.Site
	for _, entry := range siteEntries {
		site := audit.Site{
			Name:              entry.GetAttributeValue("name"),
			DistinguishedName: entry.DN,
			Description:       entry.GetAttributeValue("description"),
		}

		// Find DCs (nTDSDSA objects) in this site's Servers container
		serversDN := "CN=Servers," + entry.DN
		serverFilter := "(objectClass=server)"
		serverEntries, err := c.search(ctx, serversDN, serverFilter, []string{"dNSHostName", "name"}, 0)
		if err == nil {
			for _, se := range serverEntries {
				hostname := se.GetAttributeValue("dNSHostName")
				if hostname == "" {
					hostname = se.GetAttributeValue("name")
				}
				if hostname != "" {
					site.Servers = append(site.Servers, hostname)
				}
			}
		}

		sites = append(sites, site)
	}

	// Query Subnets
	subnetsDN := "CN=Subnets," + sitesDN
	subnetFilter := "(objectClass=subnet)"
	subnetAttrs := []string{"name", "description", "siteObject"}
	subnetEntries, err := c.search(ctx, subnetsDN, subnetFilter, subnetAttrs, 0)
	if err != nil {
		// Subnets container may not exist
		return sites, nil, nil
	}

	var subnets []audit.Subnet
	for _, entry := range subnetEntries {
		subnet := audit.Subnet{
			Name:              entry.GetAttributeValue("name"),
			DistinguishedName: entry.DN,
			SiteDN:            entry.GetAttributeValue("siteObject"),
			Description:       entry.GetAttributeValue("description"),
		}
		subnets = append(subnets, subnet)
	}

	return sites, subnets, nil
}

// GetReplMetadata reads msDS-ReplAttributeMetaData for a single object DN and
// returns the last-changed time for each attribute.
func (c *Client) GetReplMetadata(ctx context.Context, dn string) ([]audit.ReplMetadataEntry, error) {
	entries, err := c.search(ctx, dn, "(objectClass=*)", []string{"msDS-ReplAttributeMetaData"}, 1)
	if err != nil || len(entries) == 0 {
		return nil, err
	}

	rawValues := entries[0].GetAttributeValues("msDS-ReplAttributeMetaData")
	var results []audit.ReplMetadataEntry
	for _, raw := range rawValues {
		entry := parseReplMetadataXML(raw)
		if entry.AttributeName != "" {
			results = append(results, entry)
		}
	}
	return results, nil
}

// GetReplValueMetadata reads msDS-ReplValueMetaData for a link-valued attribute (e.g. member).
// Returns a map of linked value DN → last change time.
func (c *Client) GetReplValueMetadata(ctx context.Context, dn string) (map[string]time.Time, error) {
	entries, err := c.search(ctx, dn, "(objectClass=*)", []string{"msDS-ReplValueMetaData"}, 1)
	if err != nil || len(entries) == 0 {
		return nil, err
	}

	rawValues := entries[0].GetAttributeValues("msDS-ReplValueMetaData")
	result := make(map[string]time.Time)
	for _, raw := range rawValues {
		dn, t := parseReplValueMetadataXML(raw)
		if dn != "" && !t.IsZero() {
			result[dn] = t
		}
	}
	return result, nil
}

// parseReplMetadataXML parses a single msDS-ReplAttributeMetaData XML value.
// Format: <DS_REPL_ATTR_META_DATA><pszAttributeName>attr</pszAttributeName>
// <ftimeLastOriginatingChange>YYYY-MM-DDTHH:MM:SS</ftimeLastOriginatingChange>...</DS_REPL_ATTR_META_DATA>
func parseReplMetadataXML(xml string) audit.ReplMetadataEntry {
	var entry audit.ReplMetadataEntry
	entry.AttributeName = extractXMLTag(xml, "pszAttributeName")
	timeStr := extractXMLTag(xml, "ftimeLastOriginatingChange")
	if timeStr != "" {
		t, err := time.Parse("2006-01-02T15:04:05", timeStr)
		if err == nil {
			entry.LastChangeTime = t
		}
	}
	versionStr := extractXMLTag(xml, "dwVersion")
	if versionStr != "" {
		v, _ := strconv.Atoi(versionStr)
		entry.Version = v
	}
	return entry
}

// parseReplValueMetadataXML parses a single msDS-ReplValueMetaData XML value.
func parseReplValueMetadataXML(xml string) (string, time.Time) {
	dn := extractXMLTag(xml, "pszObjectDn")
	timeStr := extractXMLTag(xml, "ftimeLastOriginatingChange")
	if timeStr == "" {
		timeStr = extractXMLTag(xml, "ftimeCreated")
	}
	var t time.Time
	if timeStr != "" {
		t, _ = time.Parse("2006-01-02T15:04:05", timeStr)
	}
	return dn, t
}

// extractXMLTag extracts the text content between <tag> and </tag>
func extractXMLTag(xml, tag string) string {
	start := strings.Index(xml, "<"+tag+">")
	if start < 0 {
		return ""
	}
	start += len(tag) + 2
	end := strings.Index(xml[start:], "</"+tag+">")
	if end < 0 {
		return ""
	}
	return xml[start : start+end]
}

// functionalLevelToString converts functional level to string
func functionalLevelToString(level int) string {
	switch level {
	case 0:
		return "2000"
	case 1:
		return "2003 Interim"
	case 2:
		return "2003"
	case 3:
		return "2008"
	case 4:
		return "2008 R2"
	case 5:
		return "2012"
	case 6:
		return "2012 R2"
	case 7:
		return "2016"
	default:
		return fmt.Sprintf("Unknown (%d)", level)
	}
}
