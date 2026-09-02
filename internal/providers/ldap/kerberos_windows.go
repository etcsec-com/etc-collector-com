//go:build windows

package ldap

// Integrated authentication, Windows side (T_047/B_036).

import (
	"github.com/go-ldap/ldap/v3/gssapi"
)

// newGSSAPIClient builds the platform GSSAPI client for AuthMethod ==
// "integrated" on Windows: SSPI (secur32.dll) under the credentials of the
// current process — the account the collector service is running as
// (ideally a gMSA, whose password is managed by AD and never known to us).
// KerberosKeytab/KerberosPrincipal/KerberosCCache (the Linux/macOS knobs) are
// not applicable here and are ignored: SSPI always uses the OS's own
// negotiated ticket for the current logon session, ADS keeps it up to date
// automatically (including gMSA password rotation), and there is no
// keytab/ccache file concept on Windows to point at instead.
func (c *Client) newGSSAPIClient() (gssapiClient, error) {
	return gssapi.NewSSPIClient()
}
