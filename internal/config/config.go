// Package config handles application configuration
package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration.
//
// Every field here must have a real consumer. B_033 (T_038) removed the api: section
// and saas.dataDir, which were parsed and validated but read by nothing — an api.port
// outside 1-65535 could even refuse to start a collector over a setting no code
// consulted. See internal/config/precedence.go for how a field's value is resolved.
type Config struct {
	Server   ServerConfig   `yaml:"server" mapstructure:"server"`
	LDAP     LDAPConfig     `yaml:"ldap" mapstructure:"ldap"`
	Azure    AzureConfig    `yaml:"azure" mapstructure:"azure"`
	Audit    AuditConfig    `yaml:"audit" mapstructure:"audit"`
	Auth     AuthConfig     `yaml:"auth" mapstructure:"auth"`
	Log      LogConfig      `yaml:"log" mapstructure:"log"`
	SaaS     SaaSConfig     `yaml:"saas" mapstructure:"saas"`
	Enroll   EnrollConfig   `yaml:"enroll" mapstructure:"enroll"`
	Features FeaturesConfig `yaml:"features" mapstructure:"features"`
}

// EnrollConfig holds SaaS enrolment settings.
//
// B_033 (T_038): enroll.token already worked — it is read via
// viper.GetString("enroll.token") — but had no field here, so config.go did not
// describe a key the file genuinely accepts. The inverse of a dead section: a live
// setting invisible to anyone reading the type to learn what the file supports.
type EnrollConfig struct {
	Token string `yaml:"token" mapstructure:"token"`
}

// FeaturesConfig holds optional feature flags
type FeaturesConfig struct {
	NetworkProbes bool `yaml:"networkProbes" mapstructure:"networkProbes"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host        string `yaml:"host" mapstructure:"host"`
	Port        int    `yaml:"port" mapstructure:"port"`
	Environment string `yaml:"environment" mapstructure:"environment"`
	TLSEnabled  bool   `yaml:"tlsEnabled" mapstructure:"tlsEnabled"`
	TLSCertFile string `yaml:"tlsCertFile" mapstructure:"tlsCertFile"`
	TLSKeyFile  string `yaml:"tlsKeyFile" mapstructure:"tlsKeyFile"`
}

// LDAPConfig holds LDAP provider configuration
type LDAPConfig struct {
	URL           string        `yaml:"url" mapstructure:"url"`
	BindDN        string        `yaml:"bindDN" mapstructure:"bindDN"`
	BindPassword  string        `yaml:"bindPassword" mapstructure:"bindPassword"`
	BaseDN        string        `yaml:"baseDN" mapstructure:"baseDN"`
	TLSVerify     bool          `yaml:"tlsVerify" mapstructure:"tlsVerify"`
	TLSCACert     string        `yaml:"tlsCACert" mapstructure:"tlsCACert"`         // Path to CA certificate file
	TLSCACertPEM  string        `yaml:"tlsCACertPEM" mapstructure:"tlsCACertPEM"`   // Inline PEM content (takes precedence over TLSCACert path)
	TLSMinVersion string        `yaml:"tlsMinVersion" mapstructure:"tlsMinVersion"` // "1.0", "1.1", "1.2", "1.3"
	StartTLS      bool          `yaml:"startTLS" mapstructure:"startTLS"`           // Use StartTLS on port 389 instead of LDAPS on 636
	Timeout       time.Duration `yaml:"timeout" mapstructure:"timeout"`
	PageSize      int           `yaml:"pageSize" mapstructure:"pageSize"`
}

// AzureConfig holds Azure AD provider configuration.
//
// Authentication is app-only and accepts either a client secret or a client
// certificate (client_assertion). Tenants that forbid secret creation — common
// in regulated and public-sector environments — use the certificate fields:
// clientCertPath points at a PEM bundle (certificate + private key) or a
// PKCS#12/.pfx file, clientCertPem carries the same PEM inline, and
// clientCertPassword is only needed for an encrypted bundle. A configured
// certificate takes precedence over a configured secret.
type AzureConfig struct {
	TenantID           string `yaml:"tenantId" mapstructure:"tenantId"`
	ClientID           string `yaml:"clientId" mapstructure:"clientId"`
	ClientSecret       string `yaml:"clientSecret" mapstructure:"clientSecret"`
	ClientCertPath     string `yaml:"clientCertPath" mapstructure:"clientCertPath"`
	ClientCertPEM      string `yaml:"clientCertPem" mapstructure:"clientCertPem"`
	ClientCertPassword string `yaml:"clientCertPassword" mapstructure:"clientCertPassword"`
}

// AuditConfig holds audit-time options not tied to a provider.
type AuditConfig struct {
	Scope ScopeConfig `yaml:"scope" mapstructure:"scope"`
	// AssetFilters is the inline exclusions config (see
	// internal/audit/exclusions). Kept as a raw map so this package avoids
	// depending on the audit tree. The CLI converts it via
	// exclusions.LoadFromMap at audit time.
	AssetFilters map[string]interface{} `yaml:"assetFilters,omitempty" mapstructure:"assetFilters"`
}

// ScopeConfig restricts the audit to a subset of detectors.
// All four lists default to empty; an empty config = run every detector.
type ScopeConfig struct {
	Profile           string   `yaml:"profile" mapstructure:"profile"`                     // "quick" | "compliance" | "pentest" | ""
	IncludeCategories []string `yaml:"includeCategories" mapstructure:"includeCategories"` // detector categories to add
	ExcludeCategories []string `yaml:"excludeCategories" mapstructure:"excludeCategories"` // detector categories to remove (wins)
	IncludeDetectors  []string `yaml:"includeDetectors" mapstructure:"includeDetectors"`   // detector IDs to add
	ExcludeDetectors  []string `yaml:"excludeDetectors" mapstructure:"excludeDetectors"`   // detector IDs to remove (wins)
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	JWTPrivateKeyPath string        `yaml:"jwtPrivateKeyPath" mapstructure:"jwtPrivateKeyPath"`
	JWTPublicKeyPath  string        `yaml:"jwtPublicKeyPath" mapstructure:"jwtPublicKeyPath"`
	TokenLifetime     time.Duration `yaml:"tokenLifetime" mapstructure:"tokenLifetime"`

	// Parsed keys (not from config file)
	PrivateKey *rsa.PrivateKey `yaml:"-" mapstructure:"-"`
	PublicKey  *rsa.PublicKey  `yaml:"-" mapstructure:"-"`
}

// LogConfig holds logging configuration
type LogConfig struct {
	Level  string `yaml:"level" mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"` // console, json
}

// SaaSConfig holds SaaS integration configuration.
//
// B_033 (T_038): dataDir was removed — the data directory comes from
// saas.DefaultDataDir()/ETCSEC_DATA_DIR and nothing ever read this field.
type SaaSConfig struct {
	URL string `yaml:"url" mapstructure:"url"`
}

// Default returns the default configuration
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Host:        "0.0.0.0",
			Port:        8443,
			Environment: "development",
			TLSEnabled:  false,
		},
		LDAP: LDAPConfig{
			TLSVerify: true,
			Timeout:   30 * time.Second,
			PageSize:  1000,
		},
		Auth: AuthConfig{
			TokenLifetime:     30 * 24 * time.Hour, // 30 days
			JWTPrivateKeyPath: "./keys/private.pem",
			JWTPublicKeyPath:  "./keys/public.pem",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "console",
		},
		SaaS: SaaSConfig{
			URL: "https://api.etcsec.com",
		},
	}
}

// Load loads configuration from file and environment
func Load(configFile string) (*Config, error) {
	cfg := Default()

	// If config file specified, use it
	if configFile != "" {
		viper.SetConfigFile(configFile)
	}

	// Read config
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
		// Config file not found, use defaults
	}

	// Unmarshal into struct
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Server port must be valid
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	// TLS config
	if c.Server.TLSEnabled {
		if c.Server.TLSCertFile == "" || c.Server.TLSKeyFile == "" {
			return fmt.Errorf("TLS enabled but cert/key files not specified")
		}
	}

	return nil
}

// LoadKeys loads RSA keys from files
func (c *Config) LoadKeys() error {
	// Load private key if path is set
	if c.Auth.JWTPrivateKeyPath != "" {
		key, err := LoadPrivateKey(c.Auth.JWTPrivateKeyPath)
		if err != nil {
			// Not fatal - may only have public key for validation
			// return fmt.Errorf("failed to load private key: %w", err)
		} else {
			c.Auth.PrivateKey = key
		}
	}

	// Load public key if path is set
	if c.Auth.JWTPublicKeyPath != "" {
		key, err := LoadPublicKey(c.Auth.JWTPublicKeyPath)
		if err != nil {
			// Not fatal - may only have private key
			// return fmt.Errorf("failed to load public key: %w", err)
		} else {
			c.Auth.PublicKey = key
		}
	}

	// If we have private key but no public key, derive public from private
	if c.Auth.PrivateKey != nil && c.Auth.PublicKey == nil {
		c.Auth.PublicKey = &c.Auth.PrivateKey.PublicKey
	}

	return nil
}

// LoadPrivateKey loads an RSA private key from a PEM file
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA")
		}
		return rsaKey, nil
	}

	return key, nil
}

// LoadPublicKey loads an RSA public key from a PEM file
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}

	return rsaPub, nil
}

// IsProd returns true if running in production mode
func (c *Config) IsProd() bool {
	return os.Getenv("NODE_ENV") == "production" || os.Getenv("GO_ENV") == "production"
}

// WriteExample writes an example config file
func WriteExample(path string) error {
	cfg := Default()

	// Set example values
	cfg.LDAP.URL = "ldaps://dc.example.com:636"
	cfg.LDAP.BindDN = "CN=service,CN=Users,DC=example,DC=com"
	cfg.LDAP.BindPassword = "${LDAP_BIND_PASSWORD}"
	cfg.LDAP.BaseDN = "DC=example,DC=com"

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
