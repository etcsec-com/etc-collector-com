package azure

import (
	"testing"
	"time"
)

func TestParseGraphMinAllowedTime(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want time.Time
		ok   bool
	}{
		{
			name: "real Graph 400 from a non-P1 tenant",
			msg:  `Graph API error 400: {"error":{"code":"UnknownError","message":"Specified argument was out of the range of valid values. (Parameter 'Minimum allowed time for activityDateTime is 4/5/2026 12:00:00 AM')"}}`,
			want: time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC),
			ok:   true,
		},
		{
			name: "PM time",
			msg:  `... Minimum allowed time for activityDateTime is 4/5/2026 11:30:00 PM ...`,
			want: time.Date(2026, 4, 5, 23, 30, 0, 0, time.UTC),
			ok:   true,
		},
		{
			name: "no marker -> not parseable",
			msg:  `random Graph error without the expected phrase`,
			ok:   false,
		},
		{
			name: "marker but garbage timestamp",
			msg:  `Minimum allowed time for activityDateTime is not-a-date`,
			ok:   false,
		},
		{
			// Real Microsoft Graph format uses U+202F (NARROW NO-BREAK SPACE)
			// between the time and AM/PM. Without normalisation, every parse
			// silently returned ok=false on prod tenants. Verified via xxd:
			//   "12:00:00\xe2\x80\xafAM" — xe280af = U+202F.
			name: "U+202F NBSP between time and AM (real Graph format)",
			msg:  "Minimum allowed time for activityDateTime is 4/5/2026 12:00:00 AM')",
			want: time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC),
			ok:   true,
		},
		{
			name: "U+00A0 NBSP variant",
			msg:  "Minimum allowed time for activityDateTime is 4/5/2026 12:00:00 PM')",
			want: time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC),
			ok:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseGraphMinAllowedTime(tc.msg)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if !got.Equal(tc.want) {
				t.Errorf("got = %v, want %v", got, tc.want)
			}
		})
	}
}
