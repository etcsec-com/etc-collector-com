package api

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/import/pingcastle"
	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/guitoken"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// maxPingCastleXMLBytes caps the upload at 50 MB — matches the frontend
// pre-validation in app.js (importPingCastle()) and protects the parser
// from runaway memory on a malformed payload.
const maxPingCastleXMLBytes = 50 * 1024 * 1024

// defaultTokenLifetime is the last-resort fallback when neither the request nor
// auth.tokenLifetime in config.yaml specifies one. Kept at the historical 24h so a
// deployment with no auth: section at all sees no change.
const defaultTokenLifetime = 24 * time.Hour

// healthHandler returns server health status
//
// T_111: "edition" used to be echoed here as "pro" on every install, even
// though v3.2.0 is a single unified binary with no edition split anymore —
// confirmed live (curl -sk https://.../health -> {"edition":"pro",...}) while
// LICENSING.md/README.md both describe one unified FSL license, making the two
// public sources contradict each other. s.edition/SetVersionInfo stay: the
// underlying Edition value in main.go still feeds the SaaS cloud wire format
// (see its comment) — only this public HTTP exposure is removed.
func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   s.version,
	})
}

// AuditRequest is the request body for running an audit
type AuditRequest struct {
	IncludeDetails *bool `json:"includeDetails"` // defaults to true when nil
	MaxUsers       int   `json:"maxUsers"`
	MaxGroups      int   `json:"maxGroups"`
	MaxComputers   int   `json:"maxComputers"`
	Async          bool  `json:"async"`
	NetworkProbes  bool  `json:"networkProbes"`
}

// runAuditHandler executes an AD audit
func (s *Server) runAuditHandler(c *gin.Context) {
	var req AuditRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// If no body provided, use defaults
		req = AuditRequest{}
	}

	// Check for async query param
	if c.Query("async") == "true" {
		req.Async = true
	}

	// Check if provider is available
	if s.engine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "provider_unavailable",
			"message": "No provider configured",
		})
		return
	}

	// Double opt-in: network probes require both server flag AND API request
	enableProbes := req.NetworkProbes && s.config.Features.NetworkProbes

	// Build warning if API requested probes but server doesn't allow
	var apiWarnings []types.Warning
	if req.NetworkProbes && !s.config.Features.NetworkProbes {
		apiWarnings = append(apiWarnings, types.Warning{
			Code:    "NETWORK_PROBES_DISABLED",
			Message: "Network probes were requested but are disabled on the server. Start the server with --enable-network-probes to enable this feature.",
			AffectedDetectors: []string{
				"ESC8_HTTP_ENROLLMENT",
				"DNS_ZONE_TRANSFER_UNRESTRICTED",
			},
		})
	}

	// Default includeDetails to true when not specified
	includeDetails := true
	if req.IncludeDetails != nil {
		includeDetails = *req.IncludeDetails
	}

	opts := audit.RunOptions{
		IncludeDetails: includeDetails,
		MaxUsers:       req.MaxUsers,
		MaxGroups:      req.MaxGroups,
		MaxComputers:   req.MaxComputers,
		Parallel:       true,
		NetworkProbes:  enableProbes,
	}

	// v3.1.24 — pin engine to LDAP provider before running an AD audit.
	// Without this, when the daemon has both LDAP and Azure providers
	// registered, the engine keeps whichever was set last (typically
	// Azure) and the "Run AD Audit" GUI action silently runs an Azure
	// audit while the response label says "ad". The SaaS-pull command
	// path already does this switch (saas/daemon.go runAuditCommand) —
	// the GUI handler was missing the same protection.
	if s.manager != nil {
		if ldapProvider, ok := s.manager.Get(providers.ProviderTypeLDAP); ok {
			s.engine.SetProvider(ldapProvider)
		}
	}

	// Async execution
	if req.Async {
		job := s.jobStore.Create("ad_audit")

		go func() {
			// Use background context — the HTTP request context is cancelled
			// as soon as the 202 response is sent, which would abort the audit.
			result, err := s.engine.Run(context.Background(), opts)
			if err != nil {
				s.jobStore.Fail(job.ID, err)
				s.logger.Error("Async audit failed", zap.Error(err))
				return
			}
			// Append API-level warnings
			result.Warnings = append(result.Warnings, apiWarnings...)
			s.jobStore.Complete(job.ID, result)
		}()

		c.JSON(http.StatusAccepted, gin.H{
			"jobId":   job.ID,
			"status":  "running",
			"message": "Audit started in background",
		})
		return
	}

	// Sync execution
	result, err := s.engine.Run(c.Request.Context(), opts)
	if err != nil {
		s.logger.Error("Audit failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "audit_failed",
			"message": err.Error(),
		})
		return
	}

	// Append API-level warnings
	result.Warnings = append(result.Warnings, apiWarnings...)

	// Convert to TypeScript-compatible format
	response := types.ConvertToTSFormat(result, "ad", s.config.LDAP.URL, s.config.LDAP.BaseDN, includeDetails)
	c.JSON(http.StatusOK, response)
}

// importPingCastleHandler accepts a raw PingCastle ad_hc_*.xml upload
// (Content-Type: application/xml, max 50 MB), parses it into an
// AuditResult, and stores it in JobStore as a completed job — same
// shape as a native AD audit so the GUI can open it via /audit/jobs/:id.
func (s *Server) importPingCastleHandler(c *gin.Context) {
	body := http.MaxBytesReader(c.Writer, c.Request.Body, maxPingCastleXMLBytes)
	xmlBytes, err := io.ReadAll(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "read_body_failed",
			"message": err.Error(),
		})
		return
	}
	if len(xmlBytes) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "empty_body",
			"message": "Request body is empty — POST the ad_hc_*.xml content as application/xml.",
		})
		return
	}

	result, err := pingcastle.Parse(xmlBytes)
	if err != nil {
		s.logger.Warn("PingCastle import parse failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "parse_failed",
			"message": err.Error(),
		})
		return
	}

	job := s.jobStore.Create("pingcastle_import")
	s.jobStore.Complete(job.ID, result)

	c.JSON(http.StatusOK, gin.H{
		"jobId":   job.ID,
		"status":  "completed",
		"message": "PingCastle report imported",
	})
}

// auditStatusHandler returns current audit status
func (s *Server) auditStatusHandler(c *gin.Context) {
	// Return current provider status
	if s.manager == nil {
		c.JSON(http.StatusOK, gin.H{
			"status":   "not_configured",
			"provider": nil,
		})
		return
	}

	provider := s.manager.Primary()
	if provider == nil {
		c.JSON(http.StatusOK, gin.H{
			"status":   "not_configured",
			"provider": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ready",
		"provider": string(provider.Type()),
	})
}

// jobSummary is what listJobsHandler renders per job. It deliberately
// excludes Result: T_138 defect 2 found that the list serialized
// types.AuditResult's own JSON tags directly (a flat shape — timestamp,
// duration, score, ...) while getJobHandler wraps the identical struct in
// the enveloped {success,provider,audit} shape via types.ConvertToTSFormat —
// two different schemas for the same jobId. The embedded GUI never reads
// result from the list (app.js loadJobs() only touches d.jobs and sorts on
// createdAt; only openAudit()'s API.getJob(id) reads result), so dropping it
// here removes the divergence without any GUI change, and stops the list
// from carrying every job's full audit payload over the wire.
type jobSummary struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	Status      JobStatus  `json:"status"`
	CreatedAt   time.Time  `json:"createdAt"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// listJobsHandler returns all jobs
func (s *Server) listJobsHandler(c *gin.Context) {
	jobs := s.jobStore.List()
	summaries := make([]jobSummary, 0, len(jobs))
	for _, job := range jobs {
		summaries = append(summaries, jobSummary{
			ID:          job.ID,
			Type:        job.Type,
			Status:      job.Status,
			CreatedAt:   job.CreatedAt,
			CompletedAt: job.CompletedAt,
			Error:       job.Error,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"jobs": summaries,
	})
}

// getJobHandler returns a specific job
func (s *Server) getJobHandler(c *gin.Context) {
	id := c.Param("id")

	job, ok := s.jobStore.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "Job not found",
		})
		return
	}

	response := gin.H{
		"id":        job.ID,
		"type":      job.Type,
		"status":    job.Status,
		"createdAt": job.CreatedAt,
	}

	if job.CompletedAt != nil {
		response["completedAt"] = job.CompletedAt
	}

	if job.Error != "" {
		response["error"] = job.Error
	}

	if job.Result != nil {
		// Convert result to TypeScript-compatible format
		response["result"] = types.ConvertToTSFormat(job.Result, "ad", s.config.LDAP.URL, s.config.LDAP.BaseDN, false)
	}

	c.JSON(http.StatusOK, response)
}

// providersInfoHandler returns available providers
func (s *Server) providersInfoHandler(c *gin.Context) {
	if s.manager == nil {
		c.JSON(http.StatusOK, gin.H{
			"providers": []interface{}{},
		})
		return
	}

	providers := s.manager.All()
	infos := make([]gin.H, 0, len(providers))

	for _, p := range providers {
		infos = append(infos, gin.H{
			"type":      string(p.Type()),
			"connected": p.IsConnected(),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"providers": infos,
	})
}

// verifyGuiTokenHandler checks if a GUI access token is valid.
// This is used by the GUI login screen before storing the token locally.
//
// B_134 (T_060): must read the hash through currentGuiTokenHash() (hot-reloaded from
// disk), not the static guiTokenHash field directly — the same distinction
// authMiddleware and guiTokenMiddleware already respect (middleware.go). In daemon
// mode guiTokenHash is never set at all (only guiTokenDir is, via SetGuiTokenDir), so
// this endpoint used to report {"valid":true,"required":false} — "no auth needed" —
// for every request regardless of what was submitted, on the mode this product ships
// in by default: an unauthenticated caller could use that to confirm the admin API
// would accept anything, without ever needing to guess a real token.
//
// Every "not a valid credential" outcome now returns the identical 200
// {"valid":false}: previously an absent/malformed token got 400 while a wrong-but-
// present one got 200 valid:false, letting a caller distinguish the two. Only a
// genuinely correct token gets a different response — that's the endpoint's job.
//
// Timing, addressed rather than assumed (this ticket's own instruction): the
// comparison itself is constant-time (guitoken.Verify uses
// crypto/subtle.ConstantTimeCompare), which is what defends against the attack that
// matters here — recovering a valid token one byte at a time across many timed
// requests. NOT equalized: the branch below that skips hashing entirely when no token
// is configured runs measurably faster than the branch that hashes and compares. That
// gap is a one-time, constant amount of work (one SHA-256 plus one comparison), not a
// per-byte oracle, and is expected to be swamped by ordinary network jitter over HTTP.
// It also discloses nothing an attacker can act on: guiTokenMiddleware and
// authMiddleware already fail-closed on that exact same "no hash configured" state
// (T_041), so knowing which branch ran doesn't grant access anywhere else.
func (s *Server) verifyGuiTokenHandler(c *gin.Context) {
	hash := s.currentGuiTokenHash()

	// No hash configured — auth is disabled. This is accurate, needed product state
	// (the GUI has to know whether to show a login screen at all), not a secret being
	// withheld from an unauthenticated caller.
	if hash == "" {
		c.JSON(http.StatusOK, gin.H{"valid": true, "required": false})
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	// A bind failure leaves req.Token at its zero value (""), which
	// guitoken.Verify already treats as never valid — so a malformed body reaches
	// the exact same response as a well-formed but wrong token, rather than a
	// distinguishable 400.
	_ = c.ShouldBindJSON(&req)

	if guitoken.Verify(hash, req.Token) {
		c.JSON(http.StatusOK, gin.H{"valid": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"valid": false})
}

// TokenRequest is the request body for creating a token
//
// B_137 (T_081): a MaxUses field used to exist here and get threaded into
// the signed JWT's claims (pkg/types.GenerateToken/TokenClaims.MaxUses), but
// nothing anywhere ever read it back — JWT validation (ValidateToken,
// authMiddleware) only checks the signature and the standard exp claim.
// There is no per-token usage-counting store in this codebase (JWTs here are
// deliberately stateless), so a caller setting maxUses:1 got the same
// unlimited-use token as one who omitted it, while believing otherwise — a
// control that exists but does nothing is worse than no control, it gives
// false assurance. Removed rather than wired up: implementing real
// enforcement means a new server-side usage-count store keyed by jti,
// persisted across restarts, which is a materially bigger and riskier change
// than this fix warrants; pkg/types/auth.go itself (GenerateToken's maxUses
// parameter, TokenClaims.MaxUses) is outside internal/api and not listed in
// any agent's files_owned, so the now-fully-unused parameter/field there is
// flagged in the delivery rather than deleted here.
type TokenRequest struct {
	Service  string `json:"service"`
	Duration string `json:"duration"` // e.g., "24h", "7d", "30d"
}

// createTokenHandler creates a new JWT token
func (s *Server) createTokenHandler(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": "Invalid request body",
		})
		return
	}

	// Token lifetime — B_037 (T_038). This used to be a hardcoded 24h while
	// auth.tokenLifetime was parsed from config.yaml, defaulted to 30 days, written
	// into the generated Windows config as 720h AND echoed back to the client by
	// /admin/config. A customer could read their own setting confirmed by our API and
	// still receive 24h tokens. Same precedence family as everything else: the explicit
	// per-request value wins over the configured one, which wins over the default.
	duration := config.ResolveDuration(defaultTokenLifetime, s.config.Auth.TokenLifetime)
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid_duration",
				"message": "Invalid duration format",
			})
			return
		}
		duration = d
	}

	// Generate token. The trailing 0 is pkg/types.GenerateToken's maxUses
	// parameter — unused (see TokenRequest's doc comment, B_137/T_081).
	token, err := types.GenerateToken(
		s.config.Auth.PrivateKey,
		"system",
		req.Service,
		duration,
		0,
	)
	if err != nil {
		s.logger.Error("Failed to generate token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "token_generation_failed",
			"message": "Failed to generate token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":     token,
		"expiresAt": time.Now().Add(duration).Format(time.RFC3339),
	})
}

// tokenInfoHandler returns info about the current token
func (s *Server) tokenInfoHandler(c *gin.Context) {
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "No token claims found",
		})
		return
	}

	tokenClaims := claims.(*types.TokenClaims)

	c.JSON(http.StatusOK, gin.H{
		"subject":   tokenClaims.Subject,
		"service":   tokenClaims.Service,
		"issuedAt":  tokenClaims.IssuedAt.Time.Format(time.RFC3339),
		"expiresAt": tokenClaims.ExpiresAt.Time.Format(time.RFC3339),
		"jti":       tokenClaims.ID,
	})
}

// validateTokenHandler validates a token
func (s *Server) validateTokenHandler(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": "Token is required",
		})
		return
	}

	claims, err := types.ValidateToken(s.config.Auth.PublicKey, req.Token)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid":   false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":     true,
		"subject":   claims.Subject,
		"service":   claims.Service,
		"expiresAt": claims.ExpiresAt.Time.Format(time.RFC3339),
	})
}

// capabilitiesHandler returns server feature capabilities
//
// T_111: checked live alongside the /health "edition" removal above — this
// handler never had an "edition" key (verified by reading every gin.H field
// below), so the ticket's premise that both endpoints exposed it only held
// for /health. TestHealthAndCapabilities_NoEditionField guards both anyway,
// so a future field addition here doesn't silently reopen the gap.
//
// B_089 (T_077): version and detectorCount were both wrong on a fresh
// install with no LDAP provider configured — version was hardcoded at
// "2.3.0" (the binary is 3.1.x), and detectorCount read s.engine.DetectorCount(),
// but s.engine is a genuinely nil *audit.Engine until a provider exists
// (NewServer only constructs one when manager.Primary() is non-nil; see
// admin.go's LDAP-config handlers for the other place it's built or torn
// down). Verified before fixing, not assumed: s.engine == nil is a real,
// load-bearing signal elsewhere (runAuditHandler refuses to run an audit
// without one) — so the fix is not "unconditionally build an engine", it's
// reading the detector catalog directly. audit.DefaultRegistry is the same
// registry NewEngine(nil, ...) always defaults to (engine.go), so this is
// the exact count a live engine would report, just not gated on one
// existing. version now mirrors what /health already reports correctly
// (s.version, set via SetVersionInfo on every startup path).
func (s *Server) capabilitiesHandler(c *gin.Context) {
	hasSYSVOL := s.engine != nil && s.engine.HasSYSVOLProvider()

	c.JSON(http.StatusOK, gin.H{
		"features": gin.H{
			"ldap":              true,
			"sysvol":            hasSYSVOL,
			"networkProbes":     s.config.Features.NetworkProbes,
			"import_pingcastle": true,
		},
		"version":       s.version,
		"detectorCount": len(audit.DefaultRegistry.All()),
	})
}
