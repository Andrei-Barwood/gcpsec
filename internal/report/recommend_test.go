package report

import (
	"testing"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

func TestBuildRecommendationsPrioritizesBySeverity(t *testing.T) {
	findings := []model.Finding{
		{
			Check:          "API Key Restrictions",
			Severity:       model.SeverityMedium,
			Recommendation: "Add API restrictions",
		},
		{
			Check:          "API Key Restrictions",
			Severity:       model.SeverityHigh,
			Recommendation: "Add API restrictions",
		},
		{
			Check:          "Mandatory Rotation",
			Severity:       model.SeverityLow,
			Recommendation: "Rotate key",
		},
	}

	recs := BuildRecommendations(findings)
	if len(recs) != 2 {
		t.Fatalf("expected 2 recommendations, got %d", len(recs))
	}

	if recs[0].Priority != "P1" {
		t.Fatalf("expected highest priority recommendation first, got %s", recs[0].Priority)
	}
	if recs[0].Count != 2 {
		t.Fatalf("expected grouped count=2, got %d", recs[0].Count)
	}
}
