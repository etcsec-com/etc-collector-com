package ldap

import (
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// trustAuthChangeFromMetadata returns the ftimeLastOriginatingChange of the
// named trust secret attribute (trustAuthOutgoing or trustAuthIncoming) from
// a TDO's msDS-ReplAttributeMetaData entries (GetReplMetadata). Returns the
// zero time when the attribute is absent from the list (never replicated, or
// the read failed/was filtered) - never a synthetic date.
func trustAuthChangeFromMetadata(entries []audit.ReplMetadataEntry, attrName string) time.Time {
	for _, e := range entries {
		if strings.EqualFold(e.AttributeName, attrName) {
			return e.LastChangeTime
		}
	}
	return time.Time{}
}

// trustAccountPwdLastSet finds the interdomain trust account for a TDO
// (userAccountControl bit INTERDOMAIN_TRUST_ACCOUNT, 0x800) by matching
// sAMAccountName == flatName + "$", case-insensitively (MS-ADTS 6.1.6.8:
// "O1!flatName=<NetBIOS Name> and O2!samAccountName=<NetBIOS Name>$").
// No prefix or substring match - an empty flatName never matches, even
// against an account literally named "$".
func trustAccountPwdLastSet(flatName string, accounts map[string]time.Time) time.Time {
	if flatName == "" {
		return time.Time{}
	}
	want := strings.ToLower(flatName) + "$"
	for sam, pwdLastSet := range accounts {
		if strings.ToLower(sam) == want {
			return pwdLastSet
		}
	}
	return time.Time{}
}

// resolveOutgoingPasswordDate applies the outgoing-direction preference
// order: replication metadata is the only source for the outgoing secret
// (the interdomain trust account only ever proves the incoming/bidirectional
// side, MS-ADTS 6.1.6.8). No metadata means no reliable date - the caller
// must not guess, e.g. from whenChanged, which is a bound, not a source.
func resolveOutgoingPasswordDate(metaDate time.Time) (time.Time, string) {
	if !metaDate.IsZero() {
		return metaDate, "replmetadata"
	}
	return time.Time{}, ""
}

// resolveIncomingPasswordDate applies the incoming-direction preference
// order: replication metadata first (the secret's own last-write), then the
// trust account's pwdLastSet. Metadata wins when both are present - the
// secret actually used is the one in the TDO (MS-NRPC <67>), and the
// account's pwdLastSet can lag it (observed with dwVersion:2 - written
// twice at account creation, not necessarily in step with a later
// TDO-side rotation).
func resolveIncomingPasswordDate(metaDate, acctDate time.Time) (time.Time, string) {
	if !metaDate.IsZero() {
		return metaDate, "replmetadata"
	}
	if !acctDate.IsZero() {
		return acctDate, "trust_account"
	}
	return time.Time{}, ""
}

// trustSecretDates is GetTrusts' per-direction wiring, pulled out so it can be
// exercised directly against a literal metadata fixture instead of only
// through a live LDAP round-trip. It writes directly into trust's four
// password-date/source fields instead of returning them: a
// (time.Time, time.Time, string, string) return tuple is a same-typed
// permutation surface, and a swapped assignment at the GetTrusts call site
// (client.go) would compile clean and pass every test that only exercises
// this function directly, without ever touching that call site. Taking
// *types.Trust removes that call site entirely: GetTrusts performs no
// assignment of its own, so there is nothing left there to permute.
//
// Read each direction's own msDS-ReplAttributeMetaData entry (never the
// other direction's - outgoing and incoming secrets are independent),
// resolve the interdomain trust account's pwdLastSet as the incoming-only
// fallback, then apply each direction's preference order.
func trustSecretDates(trust *types.Trust, replMeta []audit.ReplMetadataEntry, flatName string, trustAccounts map[string]time.Time) {
	outgoingMeta := trustAuthChangeFromMetadata(replMeta, "trustAuthOutgoing")
	incomingMeta := trustAuthChangeFromMetadata(replMeta, "trustAuthIncoming")
	acctPwdLastSet := trustAccountPwdLastSet(flatName, trustAccounts)

	trust.OutgoingPasswordDate, trust.OutgoingPasswordSource = resolveOutgoingPasswordDate(outgoingMeta)
	trust.IncomingPasswordDate, trust.IncomingPasswordSource = resolveIncomingPasswordDate(incomingMeta, acctPwdLastSet)
}
