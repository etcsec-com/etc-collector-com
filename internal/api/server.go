// Package api implements the REST API server
package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/logger"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/internal/web"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ConfigUpdateFunc is called when the GUI updates a provider config.
// provider is "ldap" or "azure". params contains the config fields.
type ConfigUpdateFunc func(provider string, params map[string]interface{}) error

// Server is the HTTP API server
type Server struct {
	config         *config.Config
	configPath     string
	version        string
	edition        string
	guiTokenHash   string
	guiTokenDir    string // directory containing gui-token.hash — if set, hash is reloaded from file on each request
	onConfigUpdate ConfigUpdateFunc
	router         *gin.Engine
	server         *http.Server
	manager        *providers.Manager
	engine         *audit.Engine
	logger         *zap.Logger
	jobStore       *JobStore
	// tokenIssuanceLimiter bounds POST /api/v1/auth/token — B_137 (T_081).
	tokenIssuanceLimiter *slidingWindowLimiter
}

// NewServer creates a new API server
func NewServer(cfg *config.Config, manager *providers.Manager) *Server {
	// Set gin mode based on environment
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	s := &Server{
		config:   cfg,
		router:   router,
		manager:  manager,
		logger:   logger.Global().Zap(),
		jobStore: NewJobStore(),
		// B_137 (T_081): 10 fresh JWTs per minute is generous for the real use
		// (mint once per integration/service, refreshed near expiry) while
		// still bounding an automated reissue-on-demand loop that would
		// otherwise make the token's own lifetime meaningless.
		tokenIssuanceLimiter: newSlidingWindowLimiter(10, time.Minute),
	}

	// Create audit engine with default registry
	if manager != nil {
		provider := manager.Primary()
		if provider != nil {
			s.engine = audit.NewEngine(nil, provider)
		}
	}

	s.setupMiddleware()
	s.setupRoutes()

	return s
}

// SetConfigPath sets the path where config changes will be persisted
func (s *Server) SetConfigPath(path string) {
	s.configPath = path
}

// SyncLDAPConfig updates the server's LDAP config (used by daemon to reflect credentials.json)
func (s *Server) SyncLDAPConfig(url, bindDN, baseDN string, tlsVerify bool) {
	s.config.LDAP.URL = url
	s.config.LDAP.BindDN = bindDN
	s.config.LDAP.BaseDN = baseDN
	s.config.LDAP.TLSVerify = tlsVerify
}

// SetVersionInfo sets the version and edition for health/status endpoints
func (s *Server) SetVersionInfo(version, edition string) {
	s.version = version
	s.edition = edition
}

// SetGuiTokenHash sets the GUI access token hash for authentication (static, loaded once)
func (s *Server) SetGuiTokenHash(hash string) {
	s.guiTokenHash = hash
}

// SetGuiTokenDir sets the directory from which gui-token.hash is reloaded on each request.
// This enables hot-reload after `gui-token reset` without restarting the daemon.
func (s *Server) SetGuiTokenDir(dir string) {
	s.guiTokenDir = dir
}

// SetOnConfigUpdate registers a callback invoked when the GUI updates provider config.
// In daemon mode, this persists to credentials.json and syncs to SaaS.
// In standalone mode, this is nil and admin handlers fall back to saveConfig().
func (s *Server) SetOnConfigUpdate(fn ConfigUpdateFunc) {
	s.onConfigUpdate = fn
}

// setupMiddleware configures middleware
//
// B_091 (T_077): this used to also register a corsMiddleware sending
// `Access-Control-Allow-Origin: *` on every response — any third-party page
// open in the administrator's browser could drive this admin API. Removed
// rather than narrowed to an allowlist: the embedded GUI (web.Handler(),
// served at "/" below) is always same-origin to this API, so it never needed
// CORS headers to begin with — a browser only consults them for cross-origin
// requests. There is no other browser-based consumer (grepped internal/web's
// frontend JS and the docs for any documented external origin — none), so
// the restricted policy is: none. A cross-origin browser request now gets
// blocked by the browser's own same-origin policy, with no header from this
// server inviting otherwise.
func (s *Server) setupMiddleware() {
	// Recovery middleware
	s.router.Use(gin.Recovery())

	// Logging middleware
	s.router.Use(s.loggingMiddleware())
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		s.logger.Info("HTTP request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.Int("status", status),
			zap.Duration("latency", latency),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}

// setupRoutes configures API routes
func (s *Server) setupRoutes() {
	// Health check
	s.router.GET("/health", s.healthHandler)

	// Embedded GUI — serve at root and catch-all for SPA + static assets.
	//
	// B_090 (T_077): NoRoute used to unconditionally fall back to guiHandler,
	// so an unknown /api/v1/* route (typo, removed endpoint, wrong version)
	// returned 200 + the SPA's HTML instead of a 404 — a caller checking the
	// status code would believe the request succeeded. The SPA fallback
	// itself is legitimate and stays for client-side-routed frontend paths
	// (e.g. deep-linking a GUI route on refresh); it's only wrong under
	// /api/, which is never a frontend route.
	guiHandler := gin.WrapH(web.Handler())
	s.router.GET("/", guiHandler)
	s.router.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": fmt.Sprintf("No such route: %s %s", c.Request.Method, c.Request.URL.Path),
			})
			return
		}
		guiHandler(c)
	})

	// API v1 group
	v1 := s.router.Group("/api/v1")
	{
		// Auth endpoints
		auth := v1.Group("/auth")
		{
			auth.POST("/gui-token/verify", s.verifyGuiTokenHandler)
			auth.POST("/token", s.guiTokenMiddleware(), s.rateLimitMiddleware(), s.createTokenHandler)
			auth.GET("/token/info", s.authMiddleware(), s.tokenInfoHandler)
			auth.POST("/token/validate", s.validateTokenHandler)
		}

		// Admin endpoints (config management) — protected by GUI token
		admin := v1.Group("/admin")
		admin.Use(s.guiTokenMiddleware())
		{
			admin.GET("/config", s.getConfigHandler)
			admin.PUT("/config/ldap", s.updateLDAPConfigHandler)
			admin.POST("/config/ldap/test", s.testLDAPHandler)
			admin.DELETE("/config/ldap", s.deleteLDAPConfigHandler)
		}

		// Audit endpoints
		auditGroup := v1.Group("/audit")
		auditGroup.Use(s.authMiddleware())
		{
			auditGroup.POST("/ad", s.runAuditHandler)
			auditGroup.GET("/ad/status", s.auditStatusHandler)
			auditGroup.GET("/jobs", s.listJobsHandler)
			auditGroup.GET("/jobs/:id", s.getJobHandler)
			auditGroup.POST("/import-pingcastle", s.importPingCastleHandler)
		}

		// Provider info endpoint
		info := v1.Group("/info")
		info.Use(s.authMiddleware())
		{
			info.GET("/providers", s.providersInfoHandler)
			info.GET("/capabilities", s.capabilitiesHandler)
		}
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 300 * time.Second, // Long timeout for audits
		IdleTimeout:  60 * time.Second,
	}

	s.logger.Info("Starting API server", zap.String("address", addr))
	// B_136 (T_060): this used to hardcode http:// regardless of TLSEnabled — actively
	// misleading once a non-loopback host started requiring TLS, since the printed URL
	// wouldn't even load.
	scheme := "http"
	if s.config.Server.TLSEnabled {
		scheme = "https"
	}
	s.logger.Info("Admin GUI available", zap.String("url", fmt.Sprintf("%s://localhost:%d", scheme, s.config.Server.Port)))

	if s.config.Server.TLSEnabled {
		return s.server.ListenAndServeTLS(
			s.config.Server.TLSCertFile,
			s.config.Server.TLSKeyFile,
		)
	}

	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down API server")
	return s.server.Shutdown(ctx)
}

// SetEngine replaces the audit engine (used by daemon mode when providers change)
func (s *Server) SetEngine(e *audit.Engine) {
	s.engine = e
}

// SetManager replaces the provider manager
func (s *Server) SetManager(m *providers.Manager) {
	s.manager = m
}

// SetSYSVOLProvider sets an optional SYSVOL provider on the audit engine
func (s *Server) SetSYSVOLProvider(sp audit.SYSVOLProvider) {
	if s.engine != nil {
		s.engine.SetSYSVOLProvider(sp)
	}
}

// Router returns the gin router (for testing)
func (s *Server) Router() *gin.Engine {
	return s.router
}
