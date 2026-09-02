package config

import "time"

// Configuration precedence — the single authoritative statement for the whole product.
//
// Every setting that can come from more than one source resolves in this order, first
// non-empty wins:
//
//  1. CLI flag            --tenant-id, --log-level, …
//  2. environment variable AZURE_TENANT_ID, LDAP_TLS_CA_CERT, …
//  3. config.yaml          the matching section/key
//  4. the built-in default Default()
//
// The SaaS cloud payload is deliberately NOT in that list. A collector enrolled with
// the cloud receives its provider configuration through commands and stores it in
// credentials.json (internal/saas); it never reads config.yaml for those settings, and
// config.yaml never reaches the daemon's provider setup. The two modes are independent
// by construction, so neither can silently overwrite the other — which is why the rule
// above only has to arbitrate between flag, environment and file.
//
// B_033/B_037 (T_038): before this, several sections were parsed, echoed back by the
// admin API, and never applied — the resolution simply did not exist for them, and each
// section that did resolve did it its own way. Resolve/ResolveDuration exist so the rule
// lives in ONE place; adding a fourth way to read config.yaml is how the original defect
// happened, so route new settings through here rather than reimplementing the order.
//
// Resolve returns the first non-empty value in precedence order. Callers pass the
// sources already ordered: Resolve(flag, os.Getenv("X"), cfgField).
func Resolve(sources ...string) string {
	for _, s := range sources {
		if s != "" {
			return s
		}
	}
	return ""
}

// ResolveDuration applies the same rule to a duration. Zero means "not set" at every
// level, so a config.yaml that omits the key falls through to def rather than to 0 —
// a zero timeout or a zero token lifetime is never what an operator meant.
func ResolveDuration(def time.Duration, sources ...time.Duration) time.Duration {
	for _, d := range sources {
		if d > 0 {
			return d
		}
	}
	return def
}
