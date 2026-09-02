package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/etcsec-com/etc-collector/internal/guitoken"
	"github.com/etcsec-com/etc-collector/pkg/types"
	"github.com/gin-gonic/gin"
)

// currentGuiTokenHash returns the active GUI token hash, reloading from disk if guiTokenDir is set.
func (s *Server) currentGuiTokenHash() string {
	if s.guiTokenDir != "" {
		if hash := guitoken.LoadHash(s.guiTokenDir); hash != "" {
			return hash
		}
	}
	return s.guiTokenHash
}

// authMiddleware validates JWT tokens or falls back to GUI token.
// In embedded GUI mode (daemon), JWT keys may not be configured,
// so a valid GUI token is accepted as an alternative.
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// First, try GUI token as a fallback (for embedded GUI without JWT keys)
		hash := s.currentGuiTokenHash()
		if hash != "" {
			guiToken := c.GetHeader("X-GUI-Token")
			if guiToken != "" && guitoken.Verify(hash, guiToken) {
				c.Next()
				return
			}
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Authorization header required",
			})
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid authorization header format",
			})
			return
		}

		token := parts[1]

		// Validate token
		claims, err := types.ValidateToken(s.config.Auth.PublicKey, token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid or expired token",
			})
			return
		}

		// Store claims in context
		c.Set("claims", claims)
		c.Set("token", token)

		c.Next()
	}
}

// guiTokenMiddleware validates the GUI access token, provided via the
// X-GUI-Token header.
//
// B_091 (T_077): a ?gui_token= query-string fallback used to exist here too.
// Query strings land in access logs on every hop (this server, any reverse
// proxy in front of it, browser history, outbound Referer) — a secret that
// can't be recalled once it's leaked there. Verified before removing:
// grepped this repo (including internal/web's frontend JS) for any
// constructor of a gui_token= URL — none exists, only this one reader.
// Nothing internal ever used it.
//
// Fail-closed: no hash configured means no admin access, not open access. A missing
// hash used to be treated as "dev/legacy mode" and let every request through — that is
// exactly the state of any fleet collector upgraded (rather than reinstalled) before
// gui-token existed, i.e. the default state of the installed base (T_041/B_040). The
// daemon and standalone server entrypoints now generate a hash on startup precisely so
// this branch is never the steady state in production; see guitoken.EnsureHash.
func (s *Server) guiTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		hash := s.currentGuiTokenHash()

		if hash == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "gui_token_not_configured",
				"message": "No GUI access token is configured. Run 'etc-collector gui-token reset' to generate one.",
			})
			return
		}

		token := c.GetHeader("X-GUI-Token")

		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "gui_token_required",
				"message": "GUI access token required. Provide via X-GUI-Token header.",
			})
			return
		}

		if !guitoken.Verify(hash, token) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "gui_token_invalid",
				"message": "Invalid GUI access token.",
			})
			return
		}

		c.Next()
	}
}

// slidingWindowLimiter caps how many calls may go through within a trailing
// time window. now is overridable so tests don't depend on wall-clock sleeps.
//
// B_137 (T_081): built to bound JWT issuance (see rateLimitMiddleware below)
// — nothing previously limited how often POST /api/v1/auth/token could mint
// a fresh JWT, so a token's bounded lifetime meant little if a new one could
// always be minted the instant it was next needed. Not golang.org/x/time/rate
// (not already a dependency, and a hand-rolled sliding window is small enough
// to fully own and test deterministically here).
type slidingWindowLimiter struct {
	mu   sync.Mutex
	max  int
	win  time.Duration
	now  func() time.Time
	hits []time.Time
}

func newSlidingWindowLimiter(max int, win time.Duration) *slidingWindowLimiter {
	return &slidingWindowLimiter{max: max, win: win, now: time.Now}
}

// Allow reports whether a new call may proceed, recording it if so.
func (l *slidingWindowLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoff := now.Add(-l.win)
	kept := l.hits[:0]
	for _, h := range l.hits {
		if h.After(cutoff) {
			kept = append(kept, h)
		}
	}
	l.hits = kept

	if len(l.hits) >= l.max {
		return false
	}
	l.hits = append(l.hits, now)
	return true
}

// rateLimitMiddleware bounds JWT issuance via s.tokenIssuanceLimiter — B_137
// (T_081). Was previously a no-op placeholder registered on no route; now
// wired specifically onto POST /api/v1/auth/token (server.go), the endpoint
// this ticket's "borne l'emission" requirement is about. s.tokenIssuanceLimiter
// is created in NewServer, so this is never nil in production; the guard
// below only protects ad-hoc *Server values built directly in tests.
func (s *Server) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.tokenIssuanceLimiter != nil && !s.tokenIssuanceLimiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limited",
				"message": "Too many token requests — slow down and reuse existing tokens until they expire.",
			})
			return
		}
		c.Next()
	}
}
