package ldap

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBaseDNIsEscapedInPartitionFilter covers A_004 K11: BaseDN is pushed by the
// cloud (UPDATE_CONFIG_AD / TEST_CONNECTION_AD) and was interpolated raw into
// the crossRef filter that GetDomainInfo executes to read nETBIOSName.
func TestBaseDNIsEscapedInPartitionFilter(t *testing.T) {
	t.Run("legitimate BaseDN is unchanged", func(t *testing.T) {
		// Regression guard: escaping must not alter a normal DN, otherwise the
		// NetBIOS name would stop resolving on real domains.
		got := crossRefFilter("DC=example,DC=com")
		assert.Equal(t, "(&(objectClass=crossRef)(nCName=DC=example,DC=com))", got)
	})

	t.Run("injected metacharacters are escaped", func(t *testing.T) {
		// Classic filter-injection payload: close the equality, open an OR,
		// wildcard-match everything, and leave the trailing parens balanced.
		malicious := `DC=lab,DC=local)(|(objectClass=*`
		got := crossRefFilter(malicious)

		// The metacharacters survive only in their escaped RFC 4515 form.
		assert.Contains(t, got, `\29`, "( ) must be escaped as \\29")
		assert.Contains(t, got, `\28`, "( must be escaped as \\28")
		assert.Contains(t, got, `\2a`, "* must be escaped as \\2a")

		// And no raw injection sequence remains in the filter.
		assert.NotContains(t, got, `)(|(`, "raw injected OR clause must not survive")
		assert.NotContains(t, got, `=*`, "raw wildcard must not survive")

		// The value sits entirely inside the single nCName assertion: exactly
		// two '(' and two ')' — objectClass and nCName — plus the outer AND.
		assert.Equal(t, 3, strings.Count(got, "("), "no extra filter clause was opened")
		assert.Equal(t, 3, strings.Count(got, ")"), "no extra filter clause was closed")
	})

	t.Run("escaped filter still compiles to a single AND of two equalities", func(t *testing.T) {
		packet, err := ldap.CompileFilter(crossRefFilter(`DC=lab,DC=local)(|(objectClass=*`))
		require.NoError(t, err, "filter must remain syntactically valid")
		// FilterAnd with exactly two children: objectClass and nCName.
		require.Len(t, packet.Children, 2, "injection must not add a third clause")
	})
}
