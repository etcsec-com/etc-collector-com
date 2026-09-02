package types

// FGPP represents a Fine-Grained Password Policy (Password Settings Object)
type FGPP struct {
	DN                    string   `json:"dn"`
	Name                  string   `json:"name"`
	Precedence            int      `json:"precedence"`
	MinPasswordLength     int      `json:"minPasswordLength"`
	PasswordHistoryLength int      `json:"passwordHistoryLength"`
	LockoutThreshold      int      `json:"lockoutThreshold"`
	AppliesTo             []string `json:"appliesTo,omitempty"` // msDS-PSOAppliesTo (DNs of users/groups)
}
