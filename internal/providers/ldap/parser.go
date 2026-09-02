package ldap

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LDAP attribute names
var userAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"userPrincipalName",
	"displayName",
	"description",
	"mail",
	// HR/Profile attributes for detailed affectedEntities
	"title",
	"department",
	"company",
	"manager",
	"physicalDeliveryOfficeName",
	"employeeID",
	"telephoneNumber",
	// Account control and timestamps
	"userAccountControl",
	"adminCount",
	"whenCreated",
	"whenChanged",
	"lastLogon",
	"lastLogonTimestamp",
	"pwdLastSet",
	"accountExpires",
	"lockoutTime",
	"logonCount",
	"badPwdCount",
	"primaryGroupID",
	"memberOf",
	"sIDHistory",
	"servicePrincipalName",
	"objectSid",
	// Advanced detector attributes
	"scriptPath",
	"msDS-KeyCredentialLink",
	"msDS-AllowedToDelegateTo",
	"msDS-SupportedEncryptionTypes",
	"msDS-AllowedToActOnBehalfOfOtherIdentity",
	"msDS-GroupMSAMembership",
	// Purple Knight parity attributes
	"altSecurityIdentities",
	// Unix/legacy password attributes (for A-UnixPwd detection)
	"unixUserPassword",
	"userPassword",
}

var groupAttributes = []string{
	"distinguishedName",
	"cn",
	"sAMAccountName",
	"displayName",
	"description",
	"groupType",
	"adminCount",
	"member",
	"memberOf",
	"objectSid",
	"whenCreated",
}

var computerAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"dNSHostName",
	"operatingSystem",
	"operatingSystemVersion",
	"description",
	"userAccountControl",
	"whenCreated",
	"lastLogon",
	"lastLogonTimestamp",
	"pwdLastSet",
	"servicePrincipalName",
	"memberOf",
	"objectSid",
	"ms-Mcs-AdmPwd",
	"ms-Mcs-AdmPwdExpirationTime",
	// Windows LAPS
	"msLAPS-Password",
	"msLAPS-PasswordExpirationTime",
	// Advanced detector attributes
	"whenChanged",
	"msDS-AllowedToDelegateTo",
	"msDS-AllowedToActOnBehalfOfOtherIdentity",
	"msDS-SupportedEncryptionTypes",
	// RODC credential caching attributes
	"msDS-RevealedList",
	"msDS-NeverRevealGroup",
	"msDS-AuthenticatedToAccountList",
}

// Flags for UAC indicating an RODC: both SERVER_TRUST_ACCOUNT and PARTIAL_SECRETS_ACCOUNT.
const (
	UAC_SERVER_TRUST_ACCOUNT    = 0x2000
	UAC_PARTIAL_SECRETS_ACCOUNT = 0x04000000
)

// User Account Control flags
const (
	UAC_ACCOUNTDISABLE                 = 0x0002
	UAC_LOCKOUT                        = 0x0010
	UAC_PASSWD_NOTREQD                 = 0x0020
	UAC_PASSWD_CANT_CHANGE             = 0x0040
	UAC_NORMAL_ACCOUNT                 = 0x0200
	UAC_DONT_EXPIRE_PASSWD             = 0x10000
	UAC_SMARTCARD_REQUIRED             = 0x40000
	UAC_TRUSTED_FOR_DELEGATION         = 0x80000
	UAC_NOT_DELEGATED                  = 0x100000
	UAC_USE_DES_KEY_ONLY               = 0x200000
	UAC_DONT_REQ_PREAUTH               = 0x400000
	UAC_PASSWORD_EXPIRED               = 0x800000
	UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
)

// parseUser parses an LDAP entry into a User
func parseUser(entry *ldap.Entry) types.User {
	uac := getIntAttr(entry, "userAccountControl")

	user := types.User{
		DN:                entry.DN,
		SAMAccountName:    entry.GetAttributeValue("sAMAccountName"),
		UserPrincipalName: entry.GetAttributeValue("userPrincipalName"),
		DisplayName:       entry.GetAttributeValue("displayName"),
		Description:       entry.GetAttributeValue("description"),
		Mail:              entry.GetAttributeValue("mail"),
		// HR/Profile fields
		Title:                      entry.GetAttributeValue("title"),
		Department:                 entry.GetAttributeValue("department"),
		Company:                    entry.GetAttributeValue("company"),
		Manager:                    entry.GetAttributeValue("manager"),
		PhysicalDeliveryOfficeName: entry.GetAttributeValue("physicalDeliveryOfficeName"),
		EmployeeID:                 entry.GetAttributeValue("employeeID"),
		TelephoneNumber:            entry.GetAttributeValue("telephoneNumber"),
		// Account control and timestamps
		UserAccountControl:    uac,
		AdminCount:            entry.GetAttributeValue("adminCount") == "1",
		Created:               parseADTime(entry.GetAttributeValue("whenCreated")),
		WhenChanged:           parseADTime(entry.GetAttributeValue("whenChanged")),
		LastLogon:             parseFileTime(entry.GetAttributeValue("lastLogon")),
		LastLogonTimestamp:    parseFileTime(entry.GetAttributeValue("lastLogonTimestamp")),
		PasswordLastSet:       parseFileTime(entry.GetAttributeValue("pwdLastSet")),
		AccountExpires:        parseFileTime(entry.GetAttributeValue("accountExpires")),
		LockoutTime:           parseFileTime(entry.GetAttributeValue("lockoutTime")),
		LogonCount:            getIntAttr(entry, "logonCount"),
		BadPasswordCount:      getIntAttr(entry, "badPwdCount"),
		PrimaryGroupID:        getIntAttr(entry, "primaryGroupID"),
		MemberOf:              entry.GetAttributeValues("memberOf"),
		SIDHistory:            decodeSIDHistory(entry.GetRawAttributeValues("sIDHistory")),
		ServicePrincipalNames: entry.GetAttributeValues("servicePrincipalName"),
		ObjectSID:             decodeSID(entry.GetRawAttributeValue("objectSid")),
		// Advanced detector fields
		ScriptPath:                          entry.GetAttributeValue("scriptPath"),
		KeyCredentialLink:                   entry.GetRawAttributeValue("msDS-KeyCredentialLink"),
		AllowedToDelegateTo:                 entry.GetAttributeValues("msDS-AllowedToDelegateTo"),
		SupportedEncryptionTypes:            getIntAttr(entry, "msDS-SupportedEncryptionTypes"),
		AllowedToActOnBehalfOfOtherIdentity: entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity"),
		GMSAMembership:                      entry.GetRawAttributeValue("msDS-GroupMSAMembership"),
		AltSecurityIdentities:               entry.GetAttributeValues("altSecurityIdentities"),
	}

	// gMSA detection
	user.IsGMSA = len(user.GMSAMembership) > 0

	// Unix/legacy password attribute detection (presence only, values not stored)
	user.UnixUserPassword = len(entry.GetRawAttributeValue("unixUserPassword")) > 0
	user.UserPassword = len(entry.GetRawAttributeValue("userPassword")) > 0

	// Parse UAC flags
	user.Disabled = (uac & UAC_ACCOUNTDISABLE) != 0
	user.LockedOut = (uac & UAC_LOCKOUT) != 0
	user.PasswordNeverExpires = (uac & UAC_DONT_EXPIRE_PASSWD) != 0
	user.PasswordNotRequired = (uac & UAC_PASSWD_NOTREQD) != 0
	user.PasswordExpired = (uac & UAC_PASSWORD_EXPIRED) != 0
	user.CannotChangePassword = (uac & UAC_PASSWD_CANT_CHANGE) != 0
	user.DoesNotRequirePreAuth = (uac & UAC_DONT_REQ_PREAUTH) != 0
	user.TrustedForDelegation = (uac & UAC_TRUSTED_FOR_DELEGATION) != 0

	return user
}

// parseGroup parses an LDAP entry into a Group
func parseGroup(entry *ldap.Entry) types.Group {
	members := entry.GetAttributeValues("member")
	return types.Group{
		DN:             entry.DN,
		CN:             entry.GetAttributeValue("cn"),
		SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
		DisplayName:    entry.GetAttributeValue("displayName"),
		Description:    entry.GetAttributeValue("description"),
		GroupType:      getIntAttr(entry, "groupType"),
		AdminCount:     entry.GetAttributeValue("adminCount") == "1",
		Members:        members,
		Member:         members, // Alias — many detectors reference .Member directly
		MemberOf:       entry.GetAttributeValues("memberOf"),
		ObjectSID:      decodeSID(entry.GetRawAttributeValue("objectSid")),
		Created:        parseADTime(entry.GetAttributeValue("whenCreated")),
	}
}

// parseComputer parses an LDAP entry into a Computer
func parseComputer(entry *ldap.Entry) types.Computer {
	uac := getIntAttr(entry, "userAccountControl")

	computer := types.Computer{
		DN:                     entry.DN,
		SAMAccountName:         entry.GetAttributeValue("sAMAccountName"),
		DNSHostName:            entry.GetAttributeValue("dNSHostName"),
		OperatingSystem:        entry.GetAttributeValue("operatingSystem"),
		OperatingSystemVersion: entry.GetAttributeValue("operatingSystemVersion"),
		Description:            entry.GetAttributeValue("description"),
		UserAccountControl:     uac,
		Created:                parseADTime(entry.GetAttributeValue("whenCreated")),
		LastLogon:              parseFileTime(entry.GetAttributeValue("lastLogon")),
		LastLogonTimestamp:     parseFileTime(entry.GetAttributeValue("lastLogonTimestamp")),
		PasswordLastSet:        parseFileTime(entry.GetAttributeValue("pwdLastSet")),
		ServicePrincipalNames:  entry.GetAttributeValues("servicePrincipalName"),
		MemberOf:               entry.GetAttributeValues("memberOf"),
		ObjectSID:              decodeSID(entry.GetRawAttributeValue("objectSid")),
		LAPSPassword:           entry.GetAttributeValue("ms-Mcs-AdmPwd"),
		// Windows LAPS
		WindowsLAPSPassword: entry.GetAttributeValue("msLAPS-Password"),
		// Advanced detector fields
		WhenChanged:                         parseADTime(entry.GetAttributeValue("whenChanged")),
		AllowedToDelegateTo:                 entry.GetAttributeValues("msDS-AllowedToDelegateTo"),
		AllowedToActOnBehalfOfOtherIdentity: entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity"),
		SupportedEncryptionTypes:            getIntAttr(entry, "msDS-SupportedEncryptionTypes"),
	}

	// Parse LAPS expiry — try both the legacy (ms-Mcs-AdmPwdExpirationTime)
	// and the modern Windows LAPS (msLAPS-PasswordExpirationTime) attributes.
	// Whichever is present takes precedence; modern wins if both set.
	if lapsExpiry := entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime"); lapsExpiry != "" {
		computer.LAPSPasswordExpiry = parseFileTime(lapsExpiry)
	}
	if modernExpiry := entry.GetAttributeValue("msLAPS-PasswordExpirationTime"); modernExpiry != "" {
		computer.LAPSPasswordExpiry = parseFileTime(modernExpiry)
	}

	// Detect LAPS type
	computer.HasLegacyLAPS = computer.LAPSPassword != "" || entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime") != ""
	computer.HasWindowsLAPS = computer.WindowsLAPSPassword != "" || entry.GetAttributeValue("msLAPS-PasswordExpirationTime") != ""

	// Parse UAC flags
	computer.Disabled = (uac & UAC_ACCOUNTDISABLE) != 0
	computer.TrustedForDelegation = (uac & UAC_TRUSTED_FOR_DELEGATION) != 0
	computer.TrustedToAuthForDelegation = (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) != 0

	// RODC detection: PARTIAL_SECRETS_ACCOUNT is set on Read-Only DCs.
	computer.IsRODC = (uac & UAC_PARTIAL_SECRETS_ACCOUNT) != 0
	computer.RevealedList = entry.GetAttributeValues("msDS-RevealedList")
	computer.NeverRevealGroup = entry.GetAttributeValues("msDS-NeverRevealGroup")
	computer.AuthenticatedToAccountList = entry.GetAttributeValues("msDS-AuthenticatedToAccountList")

	return computer
}

// getIntAttr gets an integer attribute value
func getIntAttr(entry *ldap.Entry, name string) int {
	val := entry.GetAttributeValue(name)
	if val == "" {
		return 0
	}
	i, _ := strconv.Atoi(val)
	return i
}

// parseADTime parses AD generalized time format (YYYYMMDDHHmmss.0Z)
func parseADTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	// Remove trailing .0Z if present
	s = strings.TrimSuffix(s, ".0Z")
	s = strings.TrimSuffix(s, "Z")

	// Try parsing
	t, err := time.Parse("20060102150405", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// parseFileTime parses Windows FILETIME (100-nanosecond intervals since 1601-01-01)
func parseFileTime(s string) time.Time {
	if s == "" || s == "0" {
		return time.Time{}
	}

	// Parse as int64
	ft, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}

	// Never expires
	if ft == 9223372036854775807 {
		return time.Time{}
	}

	// Convert to Unix time
	// FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
	// Difference is 116444736000000000 100-nanosecond intervals
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return time.Time{}
	}

	// Convert to nanoseconds then to time
	nsec := (ft - epochDiff) * 100
	return time.Unix(0, nsec)
}

// decodeSID decodes a binary SID to string format
func decodeSID(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	revision := data[0]
	subAuthCount := int(data[1])

	// Identifier authority (6 bytes, big endian)
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(data[i])
	}

	// Build SID string
	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	// Sub-authorities (4 bytes each, little endian)
	offset := 8
	for i := 0; i < subAuthCount && offset+4 <= len(data); i++ {
		subAuth := binary.LittleEndian.Uint32(data[offset:])
		sid += fmt.Sprintf("-%d", subAuth)
		offset += 4
	}

	return sid
}

// encodeSIDFilter builds an LDAP-filter-escaped binary objectSid value
// (`\XX\XX...`) for "<domainSID>-<rid>" — the reverse of decodeSID. Used to
// resolve a well-known relative account (e.g. the built-in Administrator,
// RID 500) by SID instead of by its mutable name. Returns "" if domainSID
// isn't a well-formed "S-<revision>-<authority>-<subauth>..." string.
func encodeSIDFilter(domainSID string, rid uint32) string {
	parts := strings.Split(domainSID, "-")
	if len(parts) < 4 || parts[0] != "S" {
		return ""
	}
	revision, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return ""
	}
	authority, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return ""
	}
	subAuths := make([]uint32, 0, len(parts)-3+1)
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return ""
		}
		subAuths = append(subAuths, uint32(v))
	}
	subAuths = append(subAuths, rid)

	buf := make([]byte, 0, 8+4*len(subAuths))
	buf = append(buf, byte(revision), byte(len(subAuths)))
	for i := 5; i >= 0; i-- {
		buf = append(buf, byte(authority>>(8*i)))
	}
	for _, sa := range subAuths {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, sa)
		buf = append(buf, b...)
	}

	var sb strings.Builder
	for _, b := range buf {
		fmt.Fprintf(&sb, "\\%02x", b)
	}
	return sb.String()
}

// decodeSIDHistory decodes multiple SIDs from sIDHistory
func decodeSIDHistory(data [][]byte) []string {
	sids := make([]string, 0, len(data))
	for _, d := range data {
		if sid := decodeSID(d); sid != "" {
			sids = append(sids, sid)
		}
	}
	return sids
}

// decodeFiletimeDuration decodes a FILETIME duration (pKIExpirationPeriod, pKIOverlapPeriod).
// These are 8-byte little-endian signed int64 values representing negative 100-nanosecond intervals.
func decodeFiletimeDuration(data []byte) string {
	if len(data) != 8 {
		return ""
	}
	raw := int64(binary.LittleEndian.Uint64(data))
	if raw >= 0 {
		return ""
	}
	// Convert from negative 100ns intervals to positive seconds
	seconds := float64(-raw) / 1e7

	days := int(seconds / 86400)
	if days == 0 {
		hours := int(seconds / 3600)
		if hours > 0 {
			return fmt.Sprintf("%d hours", hours)
		}
		return ""
	}

	years := days / 365
	if years > 0 && days%365 == 0 {
		if years == 1 {
			return "1 year"
		}
		return fmt.Sprintf("%d years", years)
	}

	weeks := days / 7
	if weeks > 0 && days%7 == 0 {
		if weeks == 1 {
			return "1 week"
		}
		return fmt.Sprintf("%d weeks", weeks)
	}

	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}
