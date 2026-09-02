package trial

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/logger"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/internal/providers/azure"
	"github.com/etcsec-com/etc-collector/internal/providers/ldap"
	"github.com/etcsec-com/etc-collector/internal/providers/smb"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Executor runs trial commands with in-memory configs pushed via params.
// No persistence, no provider reuse between commands — each invocation is stateless.
type Executor struct {
	log     *logger.Logger
	version string
	edition string
}

// NewExecutor returns an executor instance.
func NewExecutor(log *logger.Logger, version, edition string) *Executor {
	if log == nil {
		log = logger.Global().Named("trial")
	}
	return &Executor{log: log, version: version, edition: edition}
}

// Execute dispatches a command to the right handler and returns a CommandResult
// ready to POST back to the trial-service. Errors are embedded in the result;
// the caller should always submit the returned result.
func (e *Executor) Execute(ctx context.Context, cmd *Command) CommandResult {
	startedAt := time.Now().UTC().Format(time.RFC3339)

	switch cmd.Type {
	case CmdTestConnectionAD:
		return e.testAD(ctx, cmd, startedAt)
	case CmdTestConnectionAzure:
		return e.testAzure(ctx, cmd, startedAt)
	case CmdRunAuditAD:
		return e.auditAD(ctx, cmd, startedAt)
	case CmdRunAuditAzure:
		return e.auditAzure(ctx, cmd, startedAt)
	default:
		return errResult(startedAt, "UNSUPPORTED_IN_TRIAL",
			fmt.Sprintf("command %q is not supported in trial mode", cmd.Type), "")
	}
}

// parseADConfig extracts an LDAP config from params["ad"] or top-level fields.
func parseADConfig(params map[string]interface{}) (ldap.Config, error) {
	adMap, ok := params["ad"].(map[string]interface{})
	if !ok || adMap == nil {
		return ldap.Config{}, fmt.Errorf("missing 'ad' object in params")
	}
	host, _ := adMap["host"].(string)
	protocol, _ := adMap["protocol"].(string)
	baseDN, _ := adMap["baseDN"].(string)
	bindDN, _ := adMap["bindDN"].(string)
	password, _ := adMap["bindPassword"].(string)
	if password == "" {
		password, _ = adMap["password"].(string)
	}
	var port int
	if v, ok := adMap["port"].(float64); ok {
		port = int(v)
	}
	if protocol == "" {
		protocol = "ldaps"
	}
	if port == 0 {
		if protocol == "ldaps" {
			port = 636
		} else {
			port = 389
		}
	}
	if host == "" {
		return ldap.Config{}, fmt.Errorf("missing 'ad.host'")
	}
	url := fmt.Sprintf("%s://%s:%d", protocol, host, port)

	cfg := ldap.Config{
		URL:          url,
		BindDN:       bindDN,
		BindPassword: password,
		BaseDN:       baseDN,
		Timeout:      30 * time.Second,
	}
	if v, ok := adMap["tlsVerify"].(bool); ok {
		cfg.TLSVerify = v
	}
	if v, ok := adMap["skipVerify"].(bool); ok {
		cfg.TLSVerify = !v
	}
	if strings.EqualFold(protocol, "ldap") {
		cfg.StartTLS = true
	}
	if ca, ok := adMap["caCertificate"].(string); ok && ca != "" {
		if strings.HasPrefix(strings.TrimSpace(ca), "-----BEGIN") {
			cfg.TLSCACertPEM = ca
		} else {
			cfg.TLSCACert = ca
		}
	}
	return cfg, nil
}

func parseAzureConfig(params map[string]interface{}) (azure.Config, error) {
	azMap, ok := params["azure"].(map[string]interface{})
	if !ok || azMap == nil {
		return azure.Config{}, fmt.Errorf("missing 'azure' object in params")
	}
	tenantID, _ := azMap["tenantId"].(string)
	clientID, _ := azMap["clientId"].(string)
	secret, _ := azMap["clientSecret"].(string)
	certPassword, _ := azMap["clientCertPassword"].(string)

	// Certificate auth (client_assertion) for tenants that forbid client
	// secrets. Same path-or-inline convention as the AD CA certificate above:
	// a value starting with a PEM armour header is the material itself, and
	// anything else is a path on the collector host (the only way to reach a
	// binary PKCS#12 bundle).
	cert, _ := azMap["clientCertificate"].(string)
	cfg := azure.Config{
		TenantID:           tenantID,
		ClientID:           clientID,
		ClientSecret:       secret,
		ClientCertPassword: certPassword,
	}
	if cert != "" {
		if strings.HasPrefix(strings.TrimSpace(cert), "-----BEGIN") {
			cfg.ClientCertPEM = cert
		} else {
			cfg.ClientCertPath = cert
		}
	}

	if tenantID == "" || clientID == "" {
		return azure.Config{}, fmt.Errorf("tenantId and clientId are required")
	}
	if !cfg.HasCredential() {
		return azure.Config{}, fmt.Errorf("clientSecret or clientCertificate is required")
	}
	return cfg, nil
}

func (e *Executor) testAD(ctx context.Context, cmd *Command, startedAt string) CommandResult {
	cfg, err := parseADConfig(cmd.Params)
	if err != nil {
		return errResult(startedAt, "INVALID_PARAMETERS", err.Error(), "")
	}
	client, err := ldap.NewClient(cfg)
	if err != nil {
		return errResult(startedAt, "LDAP_CONFIG_INVALID", err.Error(), "")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = client.Connect(cctx)
	cancel()
	if err != nil {
		return ldapErrResult(startedAt, err)
	}
	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	diag := client.GetTLSDiag(dctx)
	dcancel()
	_ = client.Close()

	return okResult(startedAt, map[string]interface{}{
		"connected": true,
		"server":    cfg.URL,
		"baseDN":    cfg.BaseDN,
		"ldapDiag":  diag,
	})
}

func (e *Executor) testAzure(ctx context.Context, cmd *Command, startedAt string) CommandResult {
	cfg, err := parseAzureConfig(cmd.Params)
	if err != nil {
		return errResult(startedAt, "INVALID_PARAMETERS", err.Error(), "")
	}
	client, err := azure.NewClient(cfg)
	if err != nil {
		return errResult(startedAt, "AZURE_CONFIG_INVALID", err.Error(), "")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = client.Connect(cctx)
	cancel()
	if err != nil {
		return errResult(startedAt, "AZURE_CONNECTION_FAILED",
			fmt.Sprintf("cannot connect to tenant %s: %v", cfg.TenantID, err), "")
	}

	var tenantName string
	if info, err := client.GetDomainInfo(ctx); err == nil && info != nil {
		tenantName = info.DomainName
	}

	pctx, pcancel := context.WithTimeout(ctx, 30*time.Second)
	checks := client.CheckPermissions(pctx)
	pcancel()

	var granted, missing []string
	for _, c := range checks {
		if c.Granted {
			granted = append(granted, c.Permission)
		} else {
			missing = append(missing, c.Permission)
		}
	}

	return okResult(startedAt, map[string]interface{}{
		"connected":  true,
		"tenantId":   cfg.TenantID,
		"tenantName": tenantName,
		"permissions": map[string]interface{}{
			"granted":      granted,
			"missing":      missing,
			"total":        len(checks),
			"grantedCount": len(granted),
		},
	})
}

func (e *Executor) auditAD(ctx context.Context, cmd *Command, startedAt string) CommandResult {
	cfg, err := parseADConfig(cmd.Params)
	if err != nil {
		return errResult(startedAt, "INVALID_PARAMETERS", err.Error(), "")
	}
	client, err := ldap.NewClient(cfg)
	if err != nil {
		return errResult(startedAt, "LDAP_CONFIG_INVALID", err.Error(), "")
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = client.Connect(cctx)
	cancel()
	if err != nil {
		return ldapErrResult(startedAt, err)
	}
	defer client.Close()

	mgr := providers.NewManager()
	if err := mgr.Register(client); err != nil {
		return errResult(startedAt, "INTERNAL_ERROR", err.Error(), "")
	}
	engine := audit.NewEngine(nil, client)

	// Optional SMB/SYSVOL (best-effort, like daemon.initLDAPProvider).
	if server := extractHost(cfg.URL); server != "" {
		sc := smb.NewClient(smb.Config{
			Server:   server,
			Domain:   domainFromDN(cfg.BaseDN),
			Username: cnFromDN(cfg.BindDN),
			Password: cfg.BindPassword,
		})
		sctx, scancel := context.WithTimeout(ctx, 15*time.Second)
		if err := sc.Connect(sctx); err == nil {
			engine.SetSYSVOLProvider(sc)
			e.log.Info("Trial SMB/SYSVOL connected")
		} else {
			e.log.Warn("Trial SMB/SYSVOL connection failed, continuing without", "error", err)
		}
		scancel()
	}

	rctx, rcancel := context.WithTimeout(ctx, 10*time.Minute)
	defer rcancel()
	opts := audit.RunOptions{
		IncludeDetails: readBoolParam(cmd.Params, "includeDetails", true),
		Parallel:       true,
		NetworkProbes:  readBoolParam(cmd.Params, "networkProbes", false),
	}
	for _, w := range applyScopeFromParams(cmd.Params, &opts) {
		e.log.Warn("trial scope warning", "warning", w)
	}
	result, err := engine.Run(rctx, opts)
	if err != nil {
		return errResult(startedAt, "AUDIT_FAILED", err.Error(), "")
	}

	ts := types.ConvertToTSFormat(result, "ad", cfg.URL, cfg.BaseDN, true)
	return okResult(startedAt, ts)
}

func (e *Executor) auditAzure(ctx context.Context, cmd *Command, startedAt string) CommandResult {
	cfg, err := parseAzureConfig(cmd.Params)
	if err != nil {
		return errResult(startedAt, "INVALID_PARAMETERS", err.Error(), "")
	}
	client, err := azure.NewClient(cfg)
	if err != nil {
		return errResult(startedAt, "AZURE_CONFIG_INVALID", err.Error(), "")
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = client.Connect(cctx)
	cancel()
	if err != nil {
		return errResult(startedAt, "AZURE_CONNECTION_FAILED",
			fmt.Sprintf("cannot connect to tenant %s: %v", cfg.TenantID, err), "")
	}

	mgr := providers.NewManager()
	if err := mgr.Register(client); err != nil {
		return errResult(startedAt, "INTERNAL_ERROR", err.Error(), "")
	}
	engine := audit.NewEngine(nil, client)

	rctx, rcancel := context.WithTimeout(ctx, 15*time.Minute)
	defer rcancel()
	opts := audit.RunOptions{
		IncludeDetails: readBoolParam(cmd.Params, "includeDetails", true),
		Parallel:       true,
	}
	for _, w := range applyScopeFromParams(cmd.Params, &opts) {
		e.log.Warn("trial scope warning", "warning", w)
	}
	result, err := engine.Run(rctx, opts)
	if err != nil {
		return errResult(startedAt, "AUDIT_FAILED", err.Error(), "")
	}

	ts := types.ConvertToTSFormat(result, "azure", "", cfg.TenantID, true)
	return okResult(startedAt, ts)
}

// --- helpers ---

func okResult(startedAt string, payload interface{}) CommandResult {
	return CommandResult{
		Status:      "success",
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339),
		Result:      payload,
	}
}

func errResult(startedAt, code, message, details string) CommandResult {
	return CommandResult{
		Status:      "error",
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339),
		Error:       &ResultError{Code: code, Message: message, Details: details},
	}
}

// ldapErrResult converts a *ldap.ConnectError (or any LDAP error) into a
// structured CommandResult that the trial-service can route to a UI hint.
func ldapErrResult(startedAt string, err error) CommandResult {
	var ce *ldap.ConnectError
	if errors.As(err, &ce) {
		return errResult(startedAt, ce.Code, ce.Message,
			fmt.Sprintf("Resolution: %s\nDocs: docs/configuration/%s\nRaw: %v",
				ce.Resolution, ce.DocAnchor, ce.Raw))
	}
	return errResult(startedAt, ldap.CodeUnknown, "LDAP connection failed", err.Error())
}

func readBoolParam(params map[string]interface{}, key string, def bool) bool {
	if v, ok := params[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

func extractHost(ldapURL string) string {
	s := ldapURL
	for _, p := range []string{"ldaps://", "ldap://", "LDAPS://", "LDAP://"} {
		if strings.HasPrefix(s, p) {
			s = s[len(p):]
			break
		}
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

func domainFromDN(baseDN string) string {
	var parts []string
	for _, c := range strings.Split(baseDN, ",") {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(strings.ToUpper(c), "DC=") {
			parts = append(parts, c[3:])
		}
	}
	return strings.Join(parts, ".")
}

func cnFromDN(dn string) string {
	for _, c := range strings.Split(dn, ",") {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(strings.ToUpper(c), "CN=") {
			return c[3:]
		}
	}
	if i := strings.IndexByte(dn, '@'); i >= 0 {
		return dn[:i]
	}
	return dn
}
