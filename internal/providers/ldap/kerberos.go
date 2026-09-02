//go:build !windows

package ldap

// Integrated authentication, Linux/macOS side (T_047/B_036).

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3/gssapi"
)

// defaultKrb5Conf is the standard MIT/Heimdal krb5.conf location, used when
// Config.Krb5Config is empty.
const defaultKrb5Conf = "/etc/krb5.conf"

// newGSSAPIClient builds the platform GSSAPI client for AuthMethod ==
// "integrated" on Linux/macOS: a keytab-backed service identity when
// KerberosKeytab is configured, otherwise the ambient Kerberos ticket cache
// — the ticket that kinit, SSSD, or the OS's own Kerberos SSO already
// populated. See Config's field comments in client.go for the precedence
// this implements.
func (c *Client) newGSSAPIClient() (gssapiClient, error) {
	krb5conf := c.config.Krb5Config
	if krb5conf == "" {
		krb5conf = defaultKrb5Conf
	}
	if _, err := os.Stat(krb5conf); err != nil {
		return nil, fmt.Errorf("krb5.conf not readable at %q: %w (set Config.Krb5Config, or install one at %s)", krb5conf, err, defaultKrb5Conf)
	}

	if c.config.KerberosKeytab != "" {
		if c.config.KerberosPrincipal == "" {
			return nil, fmt.Errorf("kerberosPrincipal is required when kerberosKeytab is set (format: user@REALM)")
		}
		username, realm, err := splitKerberosPrincipal(c.config.KerberosPrincipal)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(c.config.KerberosKeytab); err != nil {
			return nil, fmt.Errorf("keytab file not found at %q: %w", c.config.KerberosKeytab, err)
		}
		return gssapi.NewClientWithKeytab(username, realm, c.config.KerberosKeytab, krb5conf)
	}

	ccache := resolveCCachePath(c.config.KerberosCCache)
	if _, err := os.Stat(ccache); err != nil {
		return nil, fmt.Errorf("no Kerberos ticket cache at %q: %w", ccache, err)
	}
	return gssapi.NewClientFromCCache(ccache, krb5conf)
}

// splitKerberosPrincipal parses "user@REALM" into its two parts.
func splitKerberosPrincipal(p string) (username, realm string, err error) {
	i := strings.LastIndex(p, "@")
	if i <= 0 || i == len(p)-1 {
		return "", "", fmt.Errorf("kerberosPrincipal %q must be in the form user@REALM", p)
	}
	return p[:i], p[i+1:], nil
}

// resolveCCachePath implements the "ambient ticket cache" lookup order:
// explicit config override, then KRB5CCNAME (stripping the standard MIT
// "FILE:" prefix if present), then the OS default per-uid cache path.
func resolveCCachePath(explicit string) string {
	if explicit != "" {
		return strings.TrimPrefix(explicit, "FILE:")
	}
	if env := os.Getenv("KRB5CCNAME"); env != "" {
		return strings.TrimPrefix(env, "FILE:")
	}
	return fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
}
