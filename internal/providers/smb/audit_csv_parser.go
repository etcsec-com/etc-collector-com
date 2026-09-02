// Package smb — parsing of audit.csv, the Advanced Audit Policy
// Configuration export format Windows writes into a GPO at
// MACHINE\Microsoft\Windows NT\Audit\audit.csv.
//
// Format (header + one row per subcategory):
//
//	Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
//	,System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3
//
// "Setting Value" is already on the same 0-3 scale (0=No Auditing,
// 1=Success, 2=Failure, 3=Success and Failure) as EventAudit's legacy
// [Event Audit] fields, so no re-interpretation is needed — only lookup by
// subcategory GUID.
package smb

import (
	"encoding/csv"
	"strconv"
	"strings"
)

// parseAuditCSV parses a GPO's Advanced Audit Policy Configuration file,
// keyed by subcategory GUID (lowercased, with braces) to its numeric
// Setting Value. Returns nil if the file has no usable rows.
func parseAuditCSV(data []byte) map[string]int {
	text := decodeText(data)

	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1 // tolerate ragged rows rather than erroring out

	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil
	}

	guidCol, valueCol := -1, -1
	for i, h := range rows[0] {
		switch strings.TrimSpace(h) {
		case "Subcategory GUID":
			guidCol = i
		case "Setting Value":
			valueCol = i
		}
	}
	if guidCol == -1 || valueCol == -1 {
		return nil
	}

	out := make(map[string]int)
	for _, row := range rows[1:] {
		if guidCol >= len(row) || valueCol >= len(row) {
			continue
		}
		guid := strings.ToLower(strings.TrimSpace(row[guidCol]))
		if guid == "" {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(row[valueCol]))
		if err != nil {
			continue
		}
		out[guid] = v
	}

	if len(out) == 0 {
		return nil
	}
	return out
}
