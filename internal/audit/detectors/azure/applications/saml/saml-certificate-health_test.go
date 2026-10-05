package saml

import (
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// buildSP is shared by the saml-certificate-*_test.go files in this package.
func buildSP(name, usage string, end time.Time) types.ServicePrincipal {
	return types.ServicePrincipal{
		DisplayName: name,
		KeyCredentials: []types.AppCredential{
			{Type: "certificate", Usage: usage, Thumbprint: "ABC", EndDate: end},
		},
	}
}
