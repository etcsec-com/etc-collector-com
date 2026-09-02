package saas

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateSaaSURL checks an enrolment URL before the collector talks to it.
//
// A_004 K8: enrolment over http:// puts the bearer token — and afterwards every
// command and every audit result, including any AD bind password UPDATE_CONFIG_AD
// carries — on the wire in the clear, and lets an on-path attacker rewrite the whole
// exchange. That also makes T_017's download-host pinning decorative, since the
// pinned host is exactly the one the attacker would be impersonating.
//
// The check runs at enrolment time only. Already-enrolled collectors read their URL
// from credentials.json and never re-validate it, so this cannot break a running fleet
// — see the delivery for the backward-compatibility reasoning.
//
// allowInsecure corresponds to the explicit --allow-insecure-saas-url flag. It relaxes
// http:// only (local backends, lab and CI harnesses); every other non-https scheme
// stays refused regardless.
func ValidateSaaSURL(raw string, allowInsecure bool) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fmt.Errorf("SaaS URL is empty")
	}

	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("SaaS URL %q is not a valid URL: %w", s, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		// The only scheme that is safe by default.
	case "http":
		if !allowInsecure {
			return fmt.Errorf("SaaS URL %q uses plaintext HTTP: the enrolment token and every "+
				"subsequent command would travel in the clear. Use https://, or pass "+
				"--allow-insecure-saas-url if this is a local test backend", s)
		}
	case "":
		return fmt.Errorf("SaaS URL %q has no scheme — use https://<host>", s)
	default:
		return fmt.Errorf("SaaS URL %q uses unsupported scheme %q — use https://", s, u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("SaaS URL %q has no host — use https://<host>", s)
	}
	return nil
}

// IsPlaintextSaaSURL reports whether the URL would enrol over cleartext HTTP. Used by
// the CLI to warn loudly when --allow-insecure-saas-url is in play.
func IsPlaintextSaaSURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "http")
}
