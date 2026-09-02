package types

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSeverityWeight(t *testing.T) {
	tests := []struct {
		severity Severity
		expected float64
	}{
		{SeverityCritical, 10.0},
		{SeverityHigh, 3.0},
		{SeverityMedium, 1.0},
		{SeverityLow, 0.2},
		{SeverityInfo, 0.0},
		{Severity("unknown"), 0.0},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.severity.Weight())
		})
	}
}

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name           string
		findings       []Finding
		totalUsers     int
		totalComputers int
		totalGroups    int
		expected       float64
	}{
		{
			name:       "no findings - perfect score",
			findings:   []Finding{},
			totalUsers: 100,
			expected:   100.0,
		},
		{
			name: "single critical user finding, 100 users",
			findings: []Finding{
				{Type: "TEST", Severity: SeverityCritical, Category: "accounts", Count: 1},
			},
			totalUsers: 100,
			// adjustedWeighted = 1*10*1.0 = 10, adjustedDenom = 100*1.0 = 100
			// ratio = 10/100 = 0.1
			// score = 100 - log10(1.1)*50 ≈ 97.9
			expected: math.Round((100.0-math.Log10(1.1)*50)*10) / 10,
		},
		{
			name: "many critical findings, few users",
			findings: []Finding{
				{Type: "TEST", Severity: SeverityCritical, Category: "accounts", Count: 50},
			},
			totalUsers: 10,
			// adjustedWeighted = 50*10*1.0 = 500, adjustedDenom = 10
			// ratio = 500/10 = 50
			expected: math.Round((100.0-math.Log10(51)*50)*10) / 10,
		},
		{
			name: "zero totals defaults denominator to 1",
			findings: []Finding{
				{Type: "TEST", Severity: SeverityMedium, Category: "accounts", Count: 5},
			},
			totalUsers: 0,
			// adjustedWeighted = 5*1*1.0 = 5, adjustedDenom = max(0, 1) = 1
			// ratio = 5/1 = 5
			expected: math.Round((100.0-math.Log10(6)*50)*10) / 10,
		},
		{
			name: "mixed severities user-only",
			findings: []Finding{
				{Type: "T1", Severity: SeverityCritical, Category: "accounts", Count: 5},
				{Type: "T2", Severity: SeverityHigh, Category: "kerberos", Count: 20},
				{Type: "T3", Severity: SeverityMedium, Category: "password", Count: 50},
				{Type: "T4", Severity: SeverityLow, Category: "accounts", Count: 100},
			},
			totalUsers: 500,
			// All user (weight 1.0): weighted = 5*10 + 20*3 + 50*1 + 100*0.2 = 180
			// adjustedDenom = 500*1.0 = 500
			// ratio = 180/500 = 0.36
			expected: math.Round((100.0-math.Log10(1.36)*50)*10) / 10,
		},
		{
			name: "extreme findings score floors at 0",
			findings: []Finding{
				{Type: "TEST", Severity: SeverityCritical, Category: "accounts", Count: 10000},
			},
			totalUsers: 1,
			expected:   0.0,
		},
		{
			name: "entity type weighting - mixed categories",
			findings: []Finding{
				{Type: "ACCOUNT_ISSUE", Severity: SeverityCritical, Category: "accounts", Count: 10}, // user: 10*10*1.0 = 100
				{Type: "COMPUTER_ISSUE", Severity: SeverityHigh, Category: "computers", Count: 20},   // computer: 20*3*0.5 = 30
				{Type: "ACL_ISSUE", Severity: SeverityMedium, Category: "permissions", Count: 1000},  // acl: 1000*1*0.1 = 100
			},
			totalUsers:     100,
			totalComputers: 200,
			totalGroups:    50,
			// adjustedWeighted = 100 + 30 + 100 = 230
			// adjustedDenom = 100*1.0 + 200*0.5 + 50*0.2 = 100+100+10 = 210
			// ratio = 230/210 ≈ 1.0952
			// score = 100 - log10(2.0952)*50
			expected: math.Round((100.0-math.Log10(230.0/210.0+1)*50)*10) / 10,
		},
		{
			name: "ACL-heavy environment (interdata-like)",
			findings: []Finding{
				// User findings: weighted 17287
				{Type: "U1", Severity: SeverityCritical, Category: "accounts", Count: 139}, // 139*10 = 1390
				{Type: "U2", Severity: SeverityHigh, Category: "kerberos", Count: 4241},    // 4241*3 = 12723
				{Type: "U3", Severity: SeverityMedium, Category: "password", Count: 2893},  // 2893*1 = 2893
				{Type: "U4", Severity: SeverityLow, Category: "accounts", Count: 1405},     // 1405*0.2 = 281
				// Computer findings: weighted 5950
				{Type: "C1", Severity: SeverityHigh, Category: "computers", Count: 1500}, // 1500*3 = 4500
				{Type: "C2", Severity: SeverityMedium, Category: "network", Count: 1450}, // 1450*1 = 1450
				// ACL findings: weighted 37697
				{Type: "A1", Severity: SeverityHigh, Category: "permissions", Count: 10232},  // 10232*3 = 30696
				{Type: "A2", Severity: SeverityMedium, Category: "permissions", Count: 7001}, // 7001*1 = 7001
			},
			totalUsers:     592,
			totalComputers: 686,
			totalGroups:    345,
			// User weighted:     (1390+12723+2893+281) * 1.0 = 17287
			// Computer weighted: (4500+1450) * 0.5 = 2975
			// ACL weighted:      (30696+7001) * 0.1 = 3769.7
			// adjustedWeighted = 17287 + 2975 + 3769.7 = 24031.7
			// adjustedDenom = 592*1.0 + 686*0.5 + 345*0.2 = 592+343+69 = 1004
			// ratio = 24031.7/1004 ≈ 23.94
			// score = 100 - log10(24.94)*50 ≈ 100 - 69.86 ≈ 30.1
			expected: math.Round((100.0-math.Log10(24031.7/1004.0+1)*50)*10) / 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, details := CalculateScore(tt.findings, tt.totalUsers, tt.totalComputers, tt.totalGroups)
			assert.Equal(t, tt.expected, score)
			assert.NotNil(t, details)
		})
	}
}

func TestCalculateScoreDetails(t *testing.T) {
	findings := []Finding{
		{Type: "USER_F", Severity: SeverityCritical, Category: "accounts", Count: 10},  // 10*10*1.0 = 100
		{Type: "COMP_F", Severity: SeverityHigh, Category: "computers", Count: 20},     // 20*3*0.5 = 30
		{Type: "ACL_F", Severity: SeverityMedium, Category: "permissions", Count: 500}, // 500*1*0.1 = 50
	}

	_, details := CalculateScore(findings, 100, 200, 50)

	assert.Equal(t, 100.0, details.WeightedByType["user"])
	assert.Equal(t, 30.0, details.WeightedByType["computer"])
	assert.Equal(t, 50.0, details.WeightedByType["acl"])
	assert.Equal(t, 180.0, details.AdjustedWeighted)
	// denom = 100*1.0 + 200*0.5 + 50*0.2 = 210
	assert.Equal(t, 210.0, details.AdjustedDenominator)
}

func TestCalculateRating(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{100.0, "low"},
		{95.0, "low"},
		{90.0, "low"},
		{70.0, "low"},
		{69.9, "medium"},
		{50.0, "medium"},
		{49.9, "high"},
		{30.0, "high"},
		{25.0, "high"},
		{24.9, "critical"},
		{0.0, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			rating := CalculateRating(tt.score)
			assert.Equal(t, tt.expected, rating)
		})
	}
}

func TestAuditStatistics(t *testing.T) {
	stats := NewAuditStatistics()

	assert.NotNil(t, stats)
	assert.NotNil(t, stats.BySeverity)
	assert.NotNil(t, stats.ByCategory)
	assert.Equal(t, 0, stats.TotalFindings)
}

func TestFindingJSON(t *testing.T) {
	finding := Finding{
		Type:        "TEST_FINDING",
		Severity:    SeverityHigh,
		Category:    "accounts",
		Title:       "Test Finding",
		Description: "This is a test finding",
		Count:       5,
	}

	data, err := finding.JSON()
	assert.NoError(t, err)
	assert.Contains(t, string(data), "TEST_FINDING")
	assert.Contains(t, string(data), "high")
}

func TestAuditResultJSON(t *testing.T) {
	result := AuditResult{
		Score:  85.3,
		Rating: "low",
		Findings: []Finding{
			{Type: "TEST", Severity: SeverityMedium, Count: 1},
		},
		Statistics: NewAuditStatistics(),
	}

	data, err := result.JSON()
	assert.NoError(t, err)
	assert.Contains(t, string(data), "85.3")
	assert.Contains(t, string(data), "low")

	prettyData, err := result.PrettyJSON()
	assert.NoError(t, err)
	assert.Contains(t, string(prettyData), "\n") // Pretty printed has newlines
}
