package types

// Warning represents a warning message in the audit response
type Warning struct {
	Code              string   `json:"code"`
	Message           string   `json:"message"`
	AffectedDetectors []string `json:"affectedDetectors,omitempty"`
}
