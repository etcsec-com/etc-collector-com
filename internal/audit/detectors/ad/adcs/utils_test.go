package adcs

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	utilsTemplateDN = "CN=Vuln,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
	utilsUnprivSID  = "S-1-5-21-1111111111-2222222222-3333333333-1105"
	utilsAdminSID   = "S-1-5-21-1111111111-2222222222-3333333333-512" // Domain Admins
)

func TestTemplateEnrollableByUnprivileged_GUIDGrant(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if !templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a Certificate-Enrollment GUID grant to a non-privileged trustee must count as enrollable")
	}
}

func TestTemplateEnrollableByUnprivileged_AutoenrollGUIDGrant(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateAutoenrollment},
	}
	if !templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a Certificate-AutoEnrollment GUID grant to a non-privileged trustee must count as enrollable")
	}
}

func TestTemplateEnrollableByUnprivileged_GenericAllGrant(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_ALLOWED", AccessMask: GenericAll},
	}
	if !templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a full-control (GenericAll) grant to a non-privileged trustee must count as enrollable")
	}
}

func TestTemplateEnrollableByUnprivileged_AdminOnlyIsNotEnrollable(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsAdminSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a grant restricted to a privileged trustee (Domain Admins) must not count as unprivileged-enrollable")
	}
}

func TestTemplateEnrollableByUnprivileged_DenyIgnored(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "deny", ObjectType: types.GUIDCertificateEnrollment},
	}
	if templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a deny ACE must not grant enrollment")
	}
}

func TestTemplateEnrollableByUnprivileged_UnrelatedRightIgnored(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDLAPSPassword},
	}
	if templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("an ACE unrelated to enrollment rights must not count as enrollable")
	}
}

func TestTemplateEnrollableByUnprivileged_OtherDNIgnored(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: "CN=Other," + utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("an ACE on a different object DN must not apply to this template")
	}
}

func TestTemplateEnrollableByUnprivileged_NoACLs(t *testing.T) {
	if templateEnrollableByUnprivileged(utilsTemplateDN, nil) {
		t.Fatal("no ACL entries means no one can be shown to enroll")
	}
}
