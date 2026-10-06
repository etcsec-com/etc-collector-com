package types

// NetworkProbeResults contains results from network probes
type NetworkProbeResults struct {
	ESC8Results    []ESC8ProbeResult    `json:"esc8Results,omitempty"`
	ZoneTransfers  []ZoneTransferResult `json:"zoneTransfers,omitempty"`
	SpoolerResults []SpoolerProbeResult `json:"spoolerResults,omitempty"`
	TLSResults     []TLSProbeResult     `json:"tlsResults,omitempty"`
}

// ESC8ProbeResult contains HTTP probe result for a CA. WebEnrollment is only
// meaningful when Determined is true: a DC whose hostname never resolved was
// never actually probed, and reporting WebEnrollment=false for it would be
// indistinguishable from a real "not exposed" finding.
type ESC8ProbeResult struct {
	CAHostname    string `json:"caHostname"`
	CAName        string `json:"caName"`
	WebEnrollment bool   `json:"webEnrollment"`
	Determined    bool   `json:"determined"`
	StatusCode    int    `json:"statusCode"`
	Error         string `json:"error,omitempty"`
}

// ZoneTransferResult contains DNS zone transfer probe result. Allowed is only
// meaningful when Determined is true - see ESC8ProbeResult.Determined.
type ZoneTransferResult struct {
	Zone        string `json:"zone"`
	Allowed     bool   `json:"allowed"`
	Determined  bool   `json:"determined"`
	RecordCount int    `json:"recordCount"`
	Error       string `json:"error,omitempty"`
}

// SpoolerProbeResult contains the Print Spooler RPC probe result for one
// domain controller. SpoolerRunning is only meaningful when Determined is
// true: proving the spoolss pipe is (or isn't) open requires an
// authenticated SMB session, which this probe does not always have - see
// probeSpooler in internal/providers/network/probes.go. When Determined is
// false, SpoolerRunning carries no signal and must not be treated as "not
// running".
type SpoolerProbeResult struct {
	DCHostname     string `json:"dcHostname"`
	SpoolerRunning bool   `json:"spoolerRunning"`
	Determined     bool   `json:"determined"`
	Error          string `json:"error,omitempty"`
}

// TLSProbeResult contains TLS version probe result for LDAPS. WeakTLS is only
// meaningful when Determined is true - see ESC8ProbeResult.Determined.
type TLSProbeResult struct {
	DCHostname string `json:"dcHostname"`
	Port       int    `json:"port"`
	WeakTLS    bool   `json:"weakTLS"` // true if TLS 1.0 or 1.1 accepted
	Determined bool   `json:"determined"`
	Error      string `json:"error,omitempty"`
}
