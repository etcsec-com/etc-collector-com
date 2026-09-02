package types

import "time"

// CertAuthority represents one Active Directory Certificate Services (ADCS)
// Enterprise CA, enumerated from CN=Enrollment Services,CN=Public Key Services,
// CN=Services,CN=Configuration,DC=...
//
// v3.1.19 — added to back ANSSI PA-099 R36 (CA risks affecting Tier 0).
// The ANSSI auditor needs to inspect the CAs themselves, not just the cert
// templates they publish: a CA with a weak ACL or an expired/SHA-1 signing
// cert lets attackers issue arbitrary certs even if templates are hardened.
type CertAuthority struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`                  // CN — typically the human label
	DNSHostName string `json:"dnsHostName,omitempty"` // server hosting the CA role

	// CA signing certificate metadata extracted by parsing the cACertificate
	// attribute via crypto/x509. Both fields zero when the cert is unreadable
	// (LDAP perm denied or attribute missing).
	CACertSHA1     string    `json:"caCertSHA1,omitempty"`     // hex SHA-1 fingerprint
	CACertNotAfter time.Time `json:"caCertNotAfter,omitempty"` // expiry timestamp
	CACertSigAlg   string    `json:"caCertSigAlg,omitempty"`   // e.g. "SHA1-RSA", "SHA256-RSA"

	// Names of templates published on this CA (from certificateTemplates
	// multi-valued attribute). Used by R36 to cross-reference template-level
	// weaknesses with their issuing CA.
	PublishedTemplates []string `json:"publishedTemplates,omitempty"`

	// HasWeakACL = true when the security descriptor on the CA object lets
	// non-admin principals (e.g. Authenticated Users) modify the CA — that
	// translates to publishing arbitrary templates / approving requests.
	HasWeakACL bool `json:"hasWeakACL,omitempty"`
}
