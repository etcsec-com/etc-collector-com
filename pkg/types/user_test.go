package types

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLAPSFieldsNeverSerialised covers A_004 K6: the collector reads cleartext
// local-admin passwords from AD (ms-Mcs-AdmPwd, msLAPS-Password) into THREE
// fields. All three must be unreachable from any marshalling path.
func TestLAPSFieldsNeverSerialised(t *testing.T) {
	c := Computer{
		SAMAccountName:      "WS-01$",
		DN:                  "CN=WS-01,OU=Workstations,DC=example,DC=com",
		LAPSPassword:        "l3g4cy-Adm-P4ss!",
		LegacyLAPSPassword:  "l3g4cy-field-P4ss!",
		WindowsLAPSPassword: "w1nd0ws-LAPS-P4ss!",
		LAPSPasswordExpiry:  time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		HasLegacyLAPS:       true,
		HasWindowsLAPS:      true,
	}

	raw, err := json.Marshal(c)
	require.NoError(t, err)
	out := string(raw)

	// No password value on the wire.
	for _, secret := range []string{c.LAPSPassword, c.LegacyLAPSPassword, c.WindowsLAPSPassword} {
		assert.NotContains(t, out, secret, "a LAPS password value reached the JSON payload")
	}

	// No legacy key names either — a consumer keying off them must fail loudly
	// rather than silently read an empty password.
	for _, key := range []string{"lapsPassword", "legacyLapsPassword", "windowsLapsPassword"} {
		assert.NotContains(t, out, `"`+key+`"`, "a LAPS password key reached the JSON payload")
	}

	// The presence signal detectors rely on must still survive serialisation.
	assert.Contains(t, out, `"hasLegacyLAPS":true`)
	assert.Contains(t, out, `"hasWindowsLAPS":true`)
	assert.Contains(t, out, `"lapsPasswordExpiry"`)
}

// TestNoSerialisableLAPSSecretFields guards the fix against a fourth field
// being added later with a json tag (e.g. an encrypted-blob attribute).
func TestNoSerialisableLAPSSecretFields(t *testing.T) {
	typ := reflect.TypeOf(Computer{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		// Only string/[]byte fields can carry a password payload; the LAPS
		// booleans and the expiry timestamp are deliberately serialisable.
		isSecretShaped := f.Type.Kind() == reflect.String ||
			(f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8)
		if !isSecretShaped || !strings.Contains(strings.ToUpper(f.Name), "LAPS") {
			continue
		}
		assert.Equal(t, "-", f.Tag.Get("json"),
			"field %s holds LAPS secret material and must be tagged json:\"-\"", f.Name)
	}
}
