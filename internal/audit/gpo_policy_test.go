package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_042 / B_041 — T_031 put RedactSecrets at the three shared entity mappers
// (user, computer, group in pkg/types/finding.go) but OUs build their
// AffectedEntity through a separate path, OUEntity here, which copied
// ou.Description raw. security proved the gap live on DC01: a test OU planted
// with the exact string T_031's own test verified as redacted for users came
// back verbatim, and INFO_DOMAIN_OU_INVENTORY fires unconditionally on every
// OU, every audit — no password-pattern precondition required.

// TestOUEntityNeverShipsACredential is the core acceptance test for part 1:
// a cleartext password in an OU's description must not survive OUEntity.
func TestOUEntityNeverShipsACredential(t *testing.T) {
	sampleDescriptions := []string{
		"pwd=Sp1ng2001! (temp account)",
		"pwd=Xk9#mQ2w! (temp account)",
		"Temp pwd: Sp1ng2001! - a changer",
	}
	secrets := []string{"Sp1ng2001!", "Xk9#mQ2w!"}

	for _, desc := range sampleDescriptions {
		ou := types.OU{
			DN:          "OU=vuln-acl-test,DC=example,DC=com",
			Name:        "vuln-acl-test",
			Description: desc,
		}
		data := &DetectorData{}

		raw, err := json.Marshal(OUEntity(ou, data))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		out := string(raw)

		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("description %q leaked the credential %q into the payload: %s", desc, secret, out)
			}
		}
		if !strings.Contains(out, types.SecretRedactionMarker) {
			t.Errorf("description %q should carry %s, got: %s", desc, types.SecretRedactionMarker, out)
		}
		// The OU itself must still be identifiable — redaction must not cost
		// the report its actionability.
		if !strings.Contains(out, "vuln-acl-test") {
			t.Errorf("the OU must still be named, got: %s", out)
		}
	}
}

// TestOUEntityLeavesOrdinaryDescriptionsAlone mirrors
// pkg/types.TestRedactSecretsLeavesOrdinaryTextAlone at the OU mapper: the
// thousands of OUs with no secret in their description must come through
// unchanged.
func TestOUEntityLeavesOrdinaryDescriptionsAlone(t *testing.T) {
	const desc = "Departement IT - Tokyo"
	ou := types.OU{DN: "OU=IT,DC=example,DC=com", Name: "IT", Description: desc}
	got := OUEntity(ou, &DetectorData{})
	if got.Description != desc {
		t.Errorf("description = %q, want unchanged %q", got.Description, desc)
	}
}
