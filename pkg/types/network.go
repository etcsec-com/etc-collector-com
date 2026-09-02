package types

// NetworkProbeResults contains results from network probes
type NetworkProbeResults struct {
	ESC8Results    []ESC8ProbeResult    `json:"esc8Results,omitempty"`
	ZoneTransfers  []ZoneTransferResult `json:"zoneTransfers,omitempty"`
	SpoolerResults []SpoolerProbeResult `json:"spoolerResults,omitempty"`
	TLSResults     []TLSProbeResult     `json:"tlsResults,omitempty"`
}

// ESC8ProbeResult contains HTTP probe result for a CA
type ESC8ProbeResult struct {
	CAHostname    string `json:"caHostname"`
	CAName        string `json:"caName"`
	WebEnrollment bool   `json:"webEnrollment"`
	StatusCode    int    `json:"statusCode"`
	Error         string `json:"error,omitempty"`
}

// ZoneTransferResult contains DNS zone transfer probe result
type ZoneTransferResult struct {
	Zone        string `json:"zone"`
	Allowed     bool   `json:"allowed"`
	RecordCount int    `json:"recordCount"`
	Error       string `json:"error,omitempty"`
}

// SpoolerProbeResult contains RPC probe result for Print Spooler service
type SpoolerProbeResult struct {
	DCHostname     string `json:"dcHostname"`
	SpoolerRunning bool   `json:"spoolerRunning"`
	Error          string `json:"error,omitempty"`
}

// TLSProbeResult contains TLS version probe result for LDAPS
type TLSProbeResult struct {
	DCHostname string `json:"dcHostname"`
	Port       int    `json:"port"`
	WeakTLS    bool   `json:"weakTLS"` // true if TLS 1.0 or 1.1 accepted
	Error      string `json:"error,omitempty"`
}
