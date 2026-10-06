package compliance

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestScore_MinLength13_NowDeducted: the password-length
// threshold was 12, looser than both CIS (14) and DISA STIG (14) - meaning
// this score could show 100/100 on a domain where CIS_PASSWORD_POLICY and
// DISA_ACCOUNT_POLICIES simultaneously report a High-severity violation for
// the exact same MinPwdLength value. Tightened to 14 to remove that
// contradiction. A domain with MinPwdLength=13 was previously "compliant"
// here; it must now be deducted.
func TestScore_MinLength13_NowDeducted(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength:     13,
		PwdHistoryLength: 24,
		LockoutThreshold: 5,
		MaxPwdAge:        60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	score, _ := findings[0].Details["score"].(int)
	if score != 90 {
		t.Errorf("score = %d, want 90 (MinPwdLength=13 < 14 must deduct 10)", score)
	}
}

// TestScore_History23_NowDeducted is the analogous fix for password history
// (was 12, now 24, matching CIS 1.1.1 / DISA WN22-AC-000040).
func TestScore_History23_NowDeducted(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength:     14,
		PwdHistoryLength: 23,
		LockoutThreshold: 5,
		MaxPwdAge:        60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	score, _ := findings[0].Details["score"].(int)
	if score != 95 {
		t.Errorf("score = %d, want 95 (PwdHistoryLength=23 < 24 must deduct 5)", score)
	}
}

// TestScore_ScopeHonestlyDisclosed: the title/description used
// to present this as an overall "Compliance Score Assessment" with no scope
// caveat. It must now disclose it only covers password policy + admin count.
func TestScore_ScopeHonestlyDisclosed(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	if findings[0].Title == "Compliance Score Assessment" {
		t.Errorf("title must no longer imply an unscoped overall assessment: %q", findings[0].Title)
	}
	if _, ok := findings[0].Details["scope"]; !ok {
		t.Errorf("Details must disclose the score's actual scope")
	}
}

// TestScore_FullyCompliant_100 is the regression check.
func TestScore_FullyCompliant_100(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	score, _ := findings[0].Details["score"].(int)
	if score != 100 {
		t.Errorf("score = %d, want 100", score)
	}
}
