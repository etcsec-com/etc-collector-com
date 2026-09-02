package config

import (
	"testing"
	"time"
)

// TestResolve_PrecedenceOrder — the rule the whole product now shares.
// Sources are passed already ordered: flag, environment, config.yaml, default.
func TestResolve_PrecedenceOrder(t *testing.T) {
	const (
		flag = "from-flag"
		env  = "from-env"
		file = "from-file"
		def  = "from-default"
	)

	tests := []struct {
		name    string
		sources []string
		want    string
	}{
		{"flag wins over everything", []string{flag, env, file, def}, flag},
		{"env wins over file and default", []string{"", env, file, def}, env},
		{"file wins over default", []string{"", "", file, def}, file},
		{"default is the last resort", []string{"", "", "", def}, def},
		{"nothing set", []string{"", "", ""}, ""},
		{"no sources at all", nil, ""},
		{"flag alone", []string{flag}, flag},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Resolve(tc.sources...); got != tc.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tc.sources, got, tc.want)
			}
		})
	}
}

// TestResolveDuration — same rule for durations, where "unset" is zero rather than "".
// A config.yaml that omits the key must fall through to the default, never to 0: a zero
// timeout or a zero token lifetime is never what an operator meant.
func TestResolveDuration(t *testing.T) {
	const def = 30 * time.Second

	tests := []struct {
		name    string
		sources []time.Duration
		want    time.Duration
	}{
		{"first non-zero wins", []time.Duration{time.Minute, time.Hour}, time.Minute},
		{"zero falls through", []time.Duration{0, time.Hour}, time.Hour},
		{"all zero yields the default", []time.Duration{0, 0}, def},
		{"no sources yields the default", nil, def},
		{"a negative duration is not a value", []time.Duration{-time.Second, time.Hour}, time.Hour},
		{"only negatives yield the default", []time.Duration{-time.Second}, def},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveDuration(def, tc.sources...); got != tc.want {
				t.Fatalf("ResolveDuration(%v, %v) = %v, want %v", def, tc.sources, got, tc.want)
			}
		})
	}
}

// TestDeadSectionsRemoved — B_033. api: and saas.dataDir were parsed, validated and
// read by nothing. A struct field with no consumer is how the original defect looked
// from the inside, so their absence is asserted rather than assumed.
func TestDeadSectionsRemoved(t *testing.T) {
	// api.port used to be validated here: a value outside 1-65535 refused to start a
	// collector over a setting no code ever consulted.
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config must validate: %v", err)
	}

	// enroll.token works via viper and now has a field describing it.
	if cfg.Enroll.Token != "" {
		t.Errorf("enroll.token should default to empty, got %q", cfg.Enroll.Token)
	}
}

// TestDefaultsUnchangedForLiveSettings — the settings this ticket makes live keep the
// values a running deployment already had, so nothing moves for a file that omits them.
func TestDefaultsUnchangedForLiveSettings(t *testing.T) {
	cfg := Default()

	if cfg.LDAP.Timeout != 30*time.Second {
		t.Errorf("ldap.timeout default = %v, want 30s (the value previously hardcoded)", cfg.LDAP.Timeout)
	}
	if cfg.Auth.TokenLifetime != 30*24*time.Hour {
		t.Errorf("auth.tokenLifetime default = %v, want 720h", cfg.Auth.TokenLifetime)
	}
	if cfg.Log.Level != "info" || cfg.Log.Format != "console" {
		t.Errorf("log defaults = %q/%q, want info/console (the values previously hardcoded)", cfg.Log.Level, cfg.Log.Format)
	}
}
