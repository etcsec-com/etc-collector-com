package smb

import (
	"reflect"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestMergeRegistrySettings_AllFieldsMerge is the T_132/D1 regression test:
// it fails if a field is ever added to audit.RegistrySettings without being
// merged by mergeRegistrySettings. It walks every field via reflection
// instead of naming them, so a newly added field is exercised automatically
// without editing this test — the failure mode this guards against is
// exactly a whitelist silently falling one field behind the struct, which is
// what let PSTranscriptionEnabled and RestrictRemoteSAM go missing for
// months.
func TestMergeRegistrySettings_AllFieldsMerge(t *testing.T) {
	typ := reflect.TypeOf(audit.RegistrySettings{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		t.Run(field.Name, func(t *testing.T) {
			if field.Type.Kind() != reflect.Ptr {
				t.Fatalf("field %s is not a pointer type (%s); mergeRegistrySettings assumes every field is one — extend the merge and this test if that changes", field.Name, field.Type)
			}

			want := samplePointer(t, field.Type.Elem())
			src := &audit.RegistrySettings{}
			reflect.ValueOf(src).Elem().Field(i).Set(want)

			dst := &audit.RegistrySettings{}
			mergeRegistrySettings(dst, src)

			got := reflect.ValueOf(dst).Elem().Field(i)
			if got.IsNil() {
				t.Fatalf("field %s was set in src but is nil in dst after merge", field.Name)
			}
			if !reflect.DeepEqual(got.Elem().Interface(), want.Elem().Interface()) {
				t.Fatalf("field %s merged with wrong value: got %v, want %v", field.Name, got.Elem().Interface(), want.Elem().Interface())
			}
		})
	}
}

// TestMergeRegistrySettings_PreservesUnsetFields confirms the merge still
// leaves a dst field untouched when src doesn't set it — the one behavior
// the T_132/D1 fix had to keep unchanged.
func TestMergeRegistrySettings_PreservesUnsetFields(t *testing.T) {
	existing := 7
	dst := &audit.RegistrySettings{RequireSMBSigningServer: &existing}
	src := &audit.RegistrySettings{}

	mergeRegistrySettings(dst, src)

	if dst.RequireSMBSigningServer == nil || *dst.RequireSMBSigningServer != 7 {
		t.Fatalf("merge clobbered a dst field that src left unset")
	}
}

func samplePointer(t *testing.T, elemType reflect.Type) reflect.Value {
	t.Helper()
	switch elemType.Kind() {
	case reflect.Int:
		v := 42
		return reflect.ValueOf(&v)
	case reflect.String:
		v := "sample-value"
		return reflect.ValueOf(&v)
	default:
		t.Fatalf("RegistrySettings gained a field of kind %s — extend samplePointer to cover it", elemType.Kind())
		return reflect.Value{}
	}
}
