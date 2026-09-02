// Package detection contains risk detection detectors.
//
// RISK_NO_ANOMALY_DETECTION (no-anomaly-detection.go) was removed in T_058
// (B_158): it fired unconditionally on every tenant with no Graph signal
// behind it ("Identity Protection anomaly detection should be enabled and
// monitored" — not a check against any collected field), and duplicated
// ground already covered by real, conditional checks in this same package:
// RISK_NO_USER_RISK_POLICY and RISK_NO_SIGNIN_RISK_POLICY both read
// data.AzureConditionalAccessPolicies and stay silent when a risk-based
// policy exists.
package detection
