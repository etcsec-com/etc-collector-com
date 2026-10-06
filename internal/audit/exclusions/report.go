package exclusions

// Report summarises what was excluded during ApplyToData / ApplyPerDetector.
// Attached to the audit result summary so every exclusion is traceable.
type Report struct {
	RulesHash    string              `json:"rulesHash,omitempty"`
	RulesVersion int                 `json:"rulesVersion"`
	AssetCounts  map[string]*Counts  `json:"assetCounts,omitempty"` // key: "users" | "computers" | "groups" | "ous"
	PerDetector  []DetectorExclusion `json:"perDetector,omitempty"`
}

// Counts is a per-type coverage breakdown.
type Counts struct {
	Total    int      `json:"total"`
	Scanned  int      `json:"scanned"`
	Excluded int      `json:"excluded"`
	Reasons  []Reason `json:"reasons,omitempty"`
}

// Reason lists how many objects a given rule matched, with a few sample DNs.
type Reason struct {
	Field     string   `json:"field"`   // "dn" | "under_ou" | "sam" | "hostname" | "name" | "regex"
	Pattern   string   `json:"pattern"` // raw rule text
	Matched   int      `json:"matched"`
	SampleDNs []string `json:"sampleDNs,omitempty"` // up to 5
}

// DetectorExclusion records a per-detector exclusion match (e.g. "LAPS_NOT_DEPLOYED
// not evaluated on 12 computers under OU=Tenable").
type DetectorExclusion struct {
	DetectorID string   `json:"detectorId"`
	Reason     string   `json:"reason,omitempty"`
	Scope      string   `json:"scope"` // "users" | "computers" | "groups" | "ous"
	Matched    int      `json:"matched"`
	SampleDNs  []string `json:"sampleDNs,omitempty"`
}

// maxSampleDNs is the number of DNs kept per Reason/DetectorExclusion entry
// (small + bounded so the audit result stays compact).
const maxSampleDNs = 5

// bumpReason increments a Reason counter (keyed by field+pattern) in the
// reasons slice, adding the DN to the sample pool if below the cap.
func bumpReason(reasons []Reason, r hitReason, dn string) []Reason {
	for i := range reasons {
		if reasons[i].Field == r.Field && reasons[i].Pattern == r.Pattern {
			reasons[i].Matched++
			if len(reasons[i].SampleDNs) < maxSampleDNs {
				reasons[i].SampleDNs = append(reasons[i].SampleDNs, dn)
			}
			return reasons
		}
	}
	return append(reasons, Reason{
		Field:     r.Field,
		Pattern:   r.Pattern,
		Matched:   1,
		SampleDNs: []string{dn},
	})
}
