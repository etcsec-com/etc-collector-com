//go:build !windows

package ldap

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitKerberosPrincipal(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantUser  string
		wantRealm string
		wantErr   bool
	}{
		{"valid", "svc-etccollector@EXAMPLE.COM", "svc-etccollector", "EXAMPLE.COM", false},
		{"empty", "", "", "", true},
		{"no at sign", "svc-etccollector", "", "", true},
		{"leading at sign", "@EXAMPLE.COM", "", "", true},
		{"trailing at sign", "svc-etccollector@", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, realm, err := splitKerberosPrincipal(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantUser, user)
			assert.Equal(t, tc.wantRealm, realm)
		})
	}
}

func TestResolveCCachePath(t *testing.T) {
	t.Run("explicit override wins over everything", func(t *testing.T) {
		t.Setenv("KRB5CCNAME", "FILE:/from/env")
		got := resolveCCachePath("/explicit/path")
		assert.Equal(t, "/explicit/path", got)
	})

	t.Run("KRB5CCNAME used when no explicit override, FILE: prefix stripped", func(t *testing.T) {
		t.Setenv("KRB5CCNAME", "FILE:/from/env")
		got := resolveCCachePath("")
		assert.Equal(t, "/from/env", got)
	})

	t.Run("OS default per-uid path when neither is set", func(t *testing.T) {
		t.Setenv("KRB5CCNAME", "")
		got := resolveCCachePath("")
		assert.Contains(t, got, "/tmp/krb5cc_")
	})
}

// TestNewGSSAPIClient_SetupErrors covers the fail-fast diagnostics (T_047):
// every one of these must fail BEFORE any network call, with a message
// Classify() maps to an actionable Kerberos code — never a bare "bind
// failed".
func TestNewGSSAPIClient_SetupErrors(t *testing.T) {
	dir := t.TempDir()
	missingPath := filepath.Join(dir, "does-not-exist")

	realKrb5Conf := filepath.Join(dir, "krb5.conf")
	require.NoError(t, os.WriteFile(realKrb5Conf, []byte("[libdefaults]\ndefault_realm = EXAMPLE.COM\n"), 0o644))

	t.Run("missing krb5.conf", func(t *testing.T) {
		c := &Client{config: Config{AuthMethod: "integrated", Krb5Config: missingPath}}
		_, err := c.newGSSAPIClient()
		require.Error(t, err)
		assert.Equal(t, CodeKerberosConfigNotFound, Classify(err).Code)
	})

	t.Run("keytab set without principal", func(t *testing.T) {
		c := &Client{config: Config{
			AuthMethod:     "integrated",
			Krb5Config:     realKrb5Conf,
			KerberosKeytab: filepath.Join(dir, "collector.keytab"),
		}}
		_, err := c.newGSSAPIClient()
		require.Error(t, err)
		assert.Equal(t, CodeKerberosKeytabNotFound, Classify(err).Code)
	})

	t.Run("keytab file missing", func(t *testing.T) {
		c := &Client{config: Config{
			AuthMethod:        "integrated",
			Krb5Config:        realKrb5Conf,
			KerberosKeytab:    missingPath,
			KerberosPrincipal: "svc-etccollector@EXAMPLE.COM",
		}}
		_, err := c.newGSSAPIClient()
		require.Error(t, err)
		assert.Equal(t, CodeKerberosKeytabNotFound, Classify(err).Code)
	})

	t.Run("bad principal format with valid keytab path", func(t *testing.T) {
		keytabPath := filepath.Join(dir, "present.keytab")
		require.NoError(t, os.WriteFile(keytabPath, []byte{5, 2}, 0o600))
		c := &Client{config: Config{
			AuthMethod:        "integrated",
			Krb5Config:        realKrb5Conf,
			KerberosKeytab:    keytabPath,
			KerberosPrincipal: "not-a-principal",
		}}
		_, err := c.newGSSAPIClient()
		require.Error(t, err)
	})

	t.Run("no ambient ccache (no keytab configured)", func(t *testing.T) {
		t.Setenv("KRB5CCNAME", missingPath)
		c := &Client{config: Config{AuthMethod: "integrated", Krb5Config: realKrb5Conf}}
		_, err := c.newGSSAPIClient()
		require.Error(t, err)
		assert.Equal(t, CodeKerberosCCacheNotFound, Classify(err).Code)
	})

	t.Run("keytab takes precedence over ccache when both could apply", func(t *testing.T) {
		// KRB5CCNAME points at a real (if empty) file, proving the keytab
		// branch is chosen — not silently falling back to ccache — because
		// the error is the keytab-specific one, not a ccache error.
		ccachePath := filepath.Join(dir, "ccache")
		require.NoError(t, os.WriteFile(ccachePath, []byte{5, 4}, 0o600))
		t.Setenv("KRB5CCNAME", ccachePath)

		c := &Client{config: Config{
			AuthMethod:        "integrated",
			Krb5Config:        realKrb5Conf,
			KerberosKeytab:    missingPath, // deliberately broken
			KerberosPrincipal: "svc-etccollector@EXAMPLE.COM",
		}}
		_, err := c.newGSSAPIClient()
		require.Error(t, err)
		assert.Equal(t, CodeKerberosKeytabNotFound, Classify(err).Code,
			"keytab must take precedence over the ambient ccache when kerberosKeytab is set")
	})
}

// TestConnect_AuthMethodPrecedence covers acceptance criterion "l'ordre de
// précédence... est explicite dans le code" at the behavioral level, without
// a live Kerberos environment: dial a local TCP listener that accepts the
// connection but implements nothing, then assert each AuthMethod takes a
// DIFFERENT, distinguishable failure path. If AuthMethod=="integrated" ever
// silently fell back to the password path (or vice versa), these two cases
// would produce the same class of error instead of two different ones.
func TestConnect_AuthMethodPrecedence(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and hold the connection open without speaking LDAP —
			// enough for DialURL to succeed; the bind attempt is what we're
			// distinguishing, not its ultimate success.
			go func(c net.Conn) { defer c.Close(); time.Sleep(200 * time.Millisecond) }(conn)
		}
	}()
	url := "ldap://" + ln.Addr().String()

	t.Run("integrated: fails on Kerberos setup, never touches BindDN/BindPassword", func(t *testing.T) {
		c, err := NewClient(Config{
			URL:          url,
			AuthMethod:   "integrated",
			Krb5Config:   "/nonexistent/krb5.conf",
			BindDN:       "CN=should-not-be-used,DC=example,DC=com",
			BindPassword: "should-not-be-read",
			Timeout:      2 * time.Second,
		})
		require.NoError(t, err)
		err = c.Connect(context.Background())
		require.Error(t, err)
		assert.Equal(t, CodeKerberosConfigNotFound, Classify(err).Code)
	})

	t.Run("password (default): never attempts Kerberos setup", func(t *testing.T) {
		c, err := NewClient(Config{
			URL:          url,
			BindDN:       "CN=svc,DC=example,DC=com",
			BindPassword: "irrelevant",
			Timeout:      2 * time.Second,
		})
		require.NoError(t, err)
		err = c.Connect(context.Background())
		require.Error(t, err) // the dummy listener can't complete a real bind
		code := Classify(err).Code
		assert.NotContains(t, code, "KRB5", "password path must never surface a Kerberos diagnostic code")
	})
}
