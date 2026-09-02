package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/internal/providers/ldap"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// LDAPConfigRequest is the request body for configuring LDAP
type LDAPConfigRequest struct {
	URL          string `json:"url" binding:"required"`
	BindDN       string `json:"bindDN"`
	BindPassword string `json:"bindPassword"`
	BaseDN       string `json:"baseDN" binding:"required"`
	TLSVerify    *bool  `json:"tlsVerify"`
}

// AzureConfigRequest is the request body for configuring Azure
type AzureConfigRequest struct {
	TenantID     string `json:"tenantId" binding:"required"`
	ClientID     string `json:"clientId" binding:"required"`
	ClientSecret string `json:"clientSecret" binding:"required"`
}

// resolveAdminBindPassword mirrors the daemon's resolveLDAPConfig guard (T_025) for the
// local admin API (T_041/B_040): a bind password already held by this server must never
// be sent to an endpoint the caller is choosing in THIS request unless the caller also
// supplies the password. The one case where reuse is safe is re-testing or re-saving the
// SAME endpoint the password was already established for — e.g. changing baseDN without
// re-typing the password. Anything else — a request naming a different URL while leaving
// bindPassword blank — must not silently forward the stored secret there.
func (s *Server) resolveAdminBindPassword(reqURL, reqPassword string) (string, error) {
	if reqPassword != "" {
		return reqPassword, nil
	}
	if s.config.LDAP.BindPassword == "" {
		return "", nil
	}
	if reqURL == s.config.LDAP.URL {
		return s.config.LDAP.BindPassword, nil
	}
	return "", fmt.Errorf(
		"refusing to send the already-configured LDAP bind password to %q: it was established for %q. "+
			"Provide bindPassword in this request to point it at a new endpoint",
		reqURL, s.config.LDAP.URL)
}

// getConfigHandler returns the current configuration (sanitized)
func (s *Server) getConfigHandler(c *gin.Context) {
	ldapConfigured := s.config.LDAP.URL != ""
	azureConfigured := s.config.Azure.TenantID != "" && s.config.Azure.ClientID != ""

	ldapInfo := gin.H{
		"configured": ldapConfigured,
	}
	if ldapConfigured {
		ldapInfo["url"] = s.config.LDAP.URL
		ldapInfo["bindDN"] = s.config.LDAP.BindDN
		ldapInfo["baseDN"] = s.config.LDAP.BaseDN
		ldapInfo["tlsVerify"] = s.config.LDAP.TLSVerify
		// Check if connected
		if s.manager != nil {
			if p, ok := s.manager.Get(providers.ProviderTypeLDAP); ok {
				ldapInfo["connected"] = p.IsConnected()
			}
		}
	}

	azureInfo := gin.H{
		"configured": azureConfigured,
	}
	if azureConfigured {
		azureInfo["tenantId"] = s.config.Azure.TenantID
		azureInfo["clientId"] = s.config.Azure.ClientID
		// Never return clientSecret
	}

	c.JSON(http.StatusOK, gin.H{
		"server": gin.H{
			"host": s.config.Server.Host,
			"port": s.config.Server.Port,
		},
		"ldap":  ldapInfo,
		"azure": azureInfo,
		"features": gin.H{
			"networkProbes": s.config.Features.NetworkProbes,
		},
		"auth": gin.H{
			"hasKeys":       s.config.Auth.PrivateKey != nil,
			"tokenLifetime": s.config.Auth.TokenLifetime.String(),
		},
	})
}

// updateLDAPConfigHandler updates LDAP configuration and reconnects
func (s *Server) updateLDAPConfigHandler(c *gin.Context) {
	var req LDAPConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": err.Error(),
		})
		return
	}

	password, err := s.resolveAdminBindPassword(req.URL, req.BindPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bind_password_required",
			"message": err.Error(),
		})
		return
	}

	tlsVerify := true
	if req.TLSVerify != nil {
		tlsVerify = *req.TLSVerify
	}

	// B_148 (T_087): this used to write req's values onto s.config.LDAP
	// HERE — before even attempting a connection — so a request naming an
	// unreachable host or bad credentials left the server's shared,
	// in-memory config (read by every other handler: GET /admin/config, an
	// in-flight audit's report labeling) pointed at that broken config even
	// though this call itself reported failure. Build and test the
	// connection from the REQUEST's values first (testLDAPHandler below
	// already does exactly this); s.config.LDAP is only touched once the
	// connection is verified, further down.
	ldapProvider, err := ldap.NewClient(ldap.Config{
		URL:           req.URL,
		BindDN:        req.BindDN,
		BindPassword:  password,
		BaseDN:        req.BaseDN,
		TLSVerify:     tlsVerify,
		TLSCACert:     s.config.LDAP.TLSCACert,
		TLSCACertPEM:  s.config.LDAP.TLSCACertPEM,
		TLSMinVersion: s.config.LDAP.TLSMinVersion,
		StartTLS:      s.config.LDAP.StartTLS,
		Timeout:       30 * time.Second,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "ldap_config_error",
			"message": err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	if err := ldapProvider.Connect(ctx); err != nil {
		c.JSON(http.StatusBadRequest, structuredLDAPErrorResponse(err))
		return
	}

	// Connection verified — now safe to mutate the shared config.
	s.config.LDAP.URL = req.URL
	s.config.LDAP.BindDN = req.BindDN
	if password != "" {
		s.config.LDAP.BindPassword = password
	}
	s.config.LDAP.BaseDN = req.BaseDN
	s.config.LDAP.TLSVerify = tlsVerify

	// In daemon mode, delegate persistence and provider rebuild to the daemon via callback
	if s.onConfigUpdate != nil {
		params := map[string]interface{}{
			"url":          req.URL,
			"bindDN":       req.BindDN,
			"bindPassword": password,
			"baseDN":       req.BaseDN,
			"tlsVerify":    tlsVerify,
		}
		if err := s.onConfigUpdate("ldap", params); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "config_update_failed",
				"message": err.Error(),
			})
			return
		}
	} else {
		// Standalone mode: register provider locally and save to config.yaml
		if s.manager != nil {
			if err := s.manager.Replace(ldapProvider); err != nil {
				if err := s.manager.Register(ldapProvider); err != nil {
					s.logger.Error("Failed to register LDAP provider", zap.Error(err))
				}
			}
		}
		s.engine = audit.NewEngine(nil, ldapProvider)
		if err := s.saveConfig(); err != nil {
			s.logger.Warn("Failed to save config to disk", zap.Error(err))
		}
	}

	s.logger.Info("LDAP provider configured and connected",
		zap.String("url", s.config.LDAP.URL),
		zap.String("baseDN", s.config.LDAP.BaseDN),
	)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "LDAP configured and connected",
	})
}

// testLDAPHandler tests LDAP connection without saving
func (s *Server) testLDAPHandler(c *gin.Context) {
	var req LDAPConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": err.Error(),
		})
		return
	}

	tlsVerify := true
	if req.TLSVerify != nil {
		tlsVerify = *req.TLSVerify
	}

	password, err := s.resolveAdminBindPassword(req.URL, req.BindPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bind_password_required",
			"message": err.Error(),
		})
		return
	}

	client, err := ldap.NewClient(ldap.Config{
		URL:           req.URL,
		BindDN:        req.BindDN,
		BindPassword:  password,
		BaseDN:        req.BaseDN,
		TLSVerify:     tlsVerify,
		TLSCACert:     s.config.LDAP.TLSCACert,
		TLSCACertPEM:  s.config.LDAP.TLSCACertPEM,
		TLSMinVersion: s.config.LDAP.TLSMinVersion,
		StartTLS:      s.config.LDAP.StartTLS,
		Timeout:       10 * time.Second,
	})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		resp := structuredLDAPErrorResponse(err)
		resp["success"] = false
		c.JSON(http.StatusOK, resp)
		return
	}
	defer client.Close()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Connection successful",
	})
}

// structuredLDAPErrorResponse builds a gin.H map carrying the LDAP error code
// and resolution when the underlying error is a *ldap.ConnectError.
func structuredLDAPErrorResponse(err error) gin.H {
	var ce *ldap.ConnectError
	if errors.As(err, &ce) {
		return gin.H{
			"error":      "ldap_connect_failed",
			"code":       ce.Code,
			"message":    ce.Message,
			"resolution": ce.Resolution,
			"docAnchor":  ce.DocAnchor,
			"raw":        fmt.Sprintf("%v", ce.Raw),
		}
	}
	return gin.H{
		"error":   "ldap_connect_failed",
		"code":    ldap.CodeUnknown,
		"message": err.Error(),
	}
}

// deleteLDAPConfigHandler removes LDAP configuration
func (s *Server) deleteLDAPConfigHandler(c *gin.Context) {
	if s.onConfigUpdate != nil {
		// Daemon mode: delegate to callback with empty params to signal deletion
		params := map[string]interface{}{
			"url":          "",
			"bindDN":       "",
			"bindPassword": "",
			"baseDN":       "",
			"delete":       true,
		}
		if err := s.onConfigUpdate("ldap", params); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "config_delete_failed",
				"message": err.Error(),
			})
			return
		}
	} else {
		// Standalone mode
		if s.manager != nil {
			if p, ok := s.manager.Get(providers.ProviderTypeLDAP); ok {
				p.Close()
			}
		}
		s.config.LDAP.URL = ""
		s.config.LDAP.BindDN = ""
		s.config.LDAP.BindPassword = ""
		s.config.LDAP.BaseDN = ""
		s.engine = nil
		if err := s.saveConfig(); err != nil {
			s.logger.Warn("Failed to save config", zap.Error(err))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "LDAP configuration removed",
	})
}

// saveConfig persists the current config to the config file
func (s *Server) saveConfig() error {
	if s.configPath == "" {
		return nil
	}

	// Build a clean config map for YAML output
	cfgMap := map[string]interface{}{
		"server": map[string]interface{}{
			"host": s.config.Server.Host,
			"port": s.config.Server.Port,
		},
		"auth": map[string]interface{}{
			"jwtPrivateKeyPath": s.config.Auth.JWTPrivateKeyPath,
			"jwtPublicKeyPath":  s.config.Auth.JWTPublicKeyPath,
			"tokenLifetime":     s.config.Auth.TokenLifetime.String(),
		},
		"log": map[string]interface{}{
			"level":  s.config.Log.Level,
			"format": s.config.Log.Format,
		},
		"features": map[string]interface{}{
			"networkProbes": s.config.Features.NetworkProbes,
		},
	}

	if s.config.LDAP.URL != "" {
		cfgMap["ldap"] = map[string]interface{}{
			"url":          s.config.LDAP.URL,
			"bindDN":       s.config.LDAP.BindDN,
			"bindPassword": s.config.LDAP.BindPassword,
			"baseDN":       s.config.LDAP.BaseDN,
			"tlsVerify":    s.config.LDAP.TLSVerify,
			"timeout":      s.config.LDAP.Timeout.String(),
			"pageSize":     s.config.LDAP.PageSize,
		}
	}

	if s.config.Azure.TenantID != "" {
		azureMap := map[string]interface{}{
			"tenantId":     s.config.Azure.TenantID,
			"clientId":     s.config.Azure.ClientID,
			"clientSecret": s.config.Azure.ClientSecret,
		}
		// The certificate fields (T_026) were missing here: any admin-API config save
		// silently dropped them from the file. Harmless while azure: was dead; now
		// that T_038 makes the section drive real audits, dropping them would delete
		// a working credential. Written only when set, so a secret-based tenant keeps
		// the same three-key output as before.
		for key, val := range map[string]string{
			"clientCertPath":     s.config.Azure.ClientCertPath,
			"clientCertPem":      s.config.Azure.ClientCertPEM,
			"clientCertPassword": s.config.Azure.ClientCertPassword,
		} {
			if val != "" {
				azureMap[key] = val
			}
		}
		cfgMap["azure"] = azureMap
	}

	data, err := yaml.Marshal(cfgMap)
	if err != nil {
		return err
	}

	return os.WriteFile(s.configPath, data, 0600)
}
