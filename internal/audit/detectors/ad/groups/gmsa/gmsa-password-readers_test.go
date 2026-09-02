package gmsa

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// buildSDWithTrustee produces a minimal valid binary security descriptor whose
// DACL contains a single ACCESS_ALLOWED ACE for the given trustee SID.
// The output can be stored in a User.GMSAMembership field to simulate
// msDS-GroupMSAMembership contents.
func buildSDWithTrustee(sidSub uint32) []byte {
	// SID: S-1-5-21-1-1-1-<sub> (5 sub-authorities total)
	sid := make([]byte, 8+5*4)
	sid[0] = 1 // revision
	sid[1] = 5 // sub-authority count
	sid[7] = 5 // identifier authority = 5 (NT)
	binary.LittleEndian.PutUint32(sid[8:], 21)
	binary.LittleEndian.PutUint32(sid[12:], 1)
	binary.LittleEndian.PutUint32(sid[16:], 1)
	binary.LittleEndian.PutUint32(sid[20:], 1)
	binary.LittleEndian.PutUint32(sid[24:], sidSub)

	// ACE: header(8) + SID
	aceSize := uint16(8 + len(sid))
	ace := make([]byte, int(aceSize))
	ace[0] = 0x00 // ACCESS_ALLOWED
	binary.LittleEndian.PutUint16(ace[2:], aceSize)
	// Access mask = 0x20 (ADS_RIGHT_DS_READ_PROP is illustrative)
	binary.LittleEndian.PutUint32(ace[4:], 0x20)
	copy(ace[8:], sid)

	// ACL: header(8) + ACE
	aclSize := uint16(8 + len(ace))
	acl := make([]byte, aclSize)
	acl[0] = 2 // revision
	binary.LittleEndian.PutUint16(acl[2:], aclSize)
	binary.LittleEndian.PutUint16(acl[4:], 1) // ACE count
	copy(acl[8:], ace)

	// SD header: revision(1) + sbz(1) + control(2) + ownerOff(4) + groupOff(4) + saclOff(4) + daclOff(4) = 20 bytes
	const hdr = 20
	sd := make([]byte, hdr+len(acl))
	sd[0] = 1                                           // revision
	binary.LittleEndian.PutUint16(sd[2:], 0x0004)       // SE_DACL_PRESENT
	binary.LittleEndian.PutUint32(sd[16:], uint32(hdr)) // DACL offset
	copy(sd[hdr:], acl)
	return sd
}

func newData(users []types.User) *audit.DetectorData {
	return &audit.DetectorData{Users: users, IncludeDetails: true}
}

func TestGMSAPasswordReaders_NonGMSAIgnored(t *testing.T) {
	d := NewGMSAPasswordReadersDetector()
	users := []types.User{{SAMAccountName: "regular", IsGMSA: false}}
	findings := d.Detect(context.Background(), newData(users))
	if findings[0].Count != 0 {
		t.Fatalf("expected count 0 for non-gMSA user, got %d", findings[0].Count)
	}
}

func TestGMSAPasswordReaders_EmptySD(t *testing.T) {
	d := NewGMSAPasswordReadersDetector()
	users := []types.User{{SAMAccountName: "svc$", IsGMSA: true, GMSAMembership: nil}}
	findings := d.Detect(context.Background(), newData(users))
	if findings[0].Count != 0 {
		t.Fatalf("expected count 0 for empty SD, got %d", findings[0].Count)
	}
}

func TestGMSAPasswordReaders_PrivilegedReaderSkipped(t *testing.T) {
	d := NewGMSAPasswordReadersDetector()
	// SID ending in -512 (Domain Admins) is well-known privileged.
	sd := buildSDWithTrustee(512)
	users := []types.User{{SAMAccountName: "svc$", IsGMSA: true, GMSAMembership: sd}}
	findings := d.Detect(context.Background(), newData(users))
	if findings[0].Count != 0 {
		t.Fatalf("expected count 0 for privileged reader, got %d", findings[0].Count)
	}
}

func TestGMSAPasswordReaders_NonPrivilegedReaderFound(t *testing.T) {
	d := NewGMSAPasswordReadersDetector()
	sd := buildSDWithTrustee(1234) // not a well-known suffix
	users := []types.User{
		{SAMAccountName: "svc$", IsGMSA: true, GMSAMembership: sd},
	}
	findings := d.Detect(context.Background(), newData(users))
	if findings[0].Count != 1 {
		t.Fatalf("expected count 1 for non-privileged reader, got %d", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Fatalf("expected severity high, got %s", findings[0].Severity)
	}
}

func TestGMSAPasswordReaders_AdminCountUserSkipped(t *testing.T) {
	d := NewGMSAPasswordReadersDetector()
	sd := buildSDWithTrustee(5000)
	// Reader SID resolves to a user with AdminCount=true → should be skipped.
	users := []types.User{
		{SAMAccountName: "svc$", IsGMSA: true, GMSAMembership: sd},
		{SAMAccountName: "adminUser", ObjectSID: "S-1-5-21-1-1-1-5000", AdminCount: true},
	}
	findings := d.Detect(context.Background(), newData(users))
	if findings[0].Count != 0 {
		t.Fatalf("expected count 0 for adminCount reader, got %d", findings[0].Count)
	}
}
