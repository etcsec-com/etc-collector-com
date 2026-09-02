package saas

import (
	"reflect"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/guitoken"
)

// B_135 (T_060): GET_LOGS returns collector.log's content over the SaaS command
// channel, so whatever is in that file is exfiltrable by anyone who can reach that
// channel. This is the second, independent layer — not writing secrets to the log in
// the first place (see guitoken.AnnounceFirstRun) is the first, and neither replaces
// the other: a redaction-only fix leaves every log already produced by an older binary
// exposed, and a write-time-only fix leaves no safety net for a future mistake.
//
// Deliberately not a hand-maintained list of secret text patterns (the trap named
// explicitly by this ticket, and the exact defect B_149 flags for RedactSecrets
// elsewhere in this codebase): a pattern list only covers what someone remembered to
// add to it. Two structural layers instead:
//
//  1. Value-based: collectSecretStrings walks every secret-holding struct the daemon
//     currently keeps in memory via reflection, picking up any field whose name ends
//     in "Password"/"Secret" or is exactly "ApiKey"/"Token" — the SAME naming
//     convention every secret field in this codebase already follows (BindPassword,
//     ClientSecret, ClientCertPassword, ApiKey). A new secret field added anywhere in
//     Credentials/LDAPOverrides/AzureOverrides is covered automatically as long as it
//     follows that convention, without touching this file.
//  2. Format-based, for a token this instance no longer holds (already rotated via
//     `gui-token reset`) but that an older log line still contains:
//     guitoken.RedactTokens, sourced from guitoken's own prefix constant rather than a
//     duplicated literal here.

// isSecretFieldName reports whether a struct field, by name alone, is expected to
// hold credential material — the naming convention every secret field in this
// codebase already follows.
func isSecretFieldName(name string) bool {
	lower := strings.ToLower(name)
	if lower == "apikey" || lower == "token" {
		return true
	}
	return strings.HasSuffix(lower, "password") || strings.HasSuffix(lower, "secret")
}

// collectSecretStrings walks v (a struct, pointer to struct, or invalid/nil value)
// recursively and appends the value of every non-empty string field whose name
// matches isSecretFieldName. Safe on nil pointers and non-struct kinds — both are
// simply skipped, so callers can pass an unconfigured or nil struct without a guard.
func collectSecretStrings(v reflect.Value, out *[]string) {
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			if isSecretFieldName(field.Name) {
				if s := fv.String(); s != "" {
					*out = append(*out, s)
				}
			}
		case reflect.Struct, reflect.Ptr:
			collectSecretStrings(fv, out)
		}
	}
}

// secretRedactionMarker replaces a matched credential in redacted log output. States
// that something was removed, without reproducing any of it.
const secretRedactionMarker = "[REDACTED:credential]"

// redactKnownSecrets replaces every occurrence of each non-empty string in secrets
// with secretRedactionMarker, then applies guitoken.RedactTokens for any token this
// instance no longer holds. Pure and side-effect-free so it's directly unit-testable
// without touching the filesystem or a running daemon.
func redactKnownSecrets(text string, secrets []string) string {
	for _, s := range secrets {
		if s == "" {
			continue
		}
		text = strings.ReplaceAll(text, s, secretRedactionMarker)
	}
	return guitoken.RedactTokens(text)
}

// knownSecretValues gathers the current value of every secret-named field held by the
// daemon — credentials.json's contents plus any locally-supplied CLI override — for
// redactKnownSecrets to scrub from GET_LOGS output.
func (d *Daemon) knownSecretValues() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	var secrets []string
	collectSecretStrings(reflect.ValueOf(d.creds), &secrets)
	collectSecretStrings(reflect.ValueOf(d.LDAPOverrides), &secrets)
	collectSecretStrings(reflect.ValueOf(d.AzureOverrides), &secrets)
	return secrets
}
