package format

import (
	"strings"
	"testing"
	"time"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

func TestMarkdownIncludesFinding(t *testing.T) {
	r := model.ScanResult{
		GeneratedAt: time.Date(2026, 2, 27, 10, 0, 0, 0, time.UTC),
		Project:     "demo-project",
		Findings: []model.Finding{
			{
				ID:             "x",
				Check:          "Zero-Code Storage",
				Severity:       model.SeverityHigh,
				Summary:        "Potential secret",
				Description:    "Secret found",
				Recommendation: "Rotate key",
			},
		},
	}

	b, err := Markdown(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := string(b)
	if !strings.Contains(text, "Potential secret") {
		t.Fatalf("markdown did not include finding summary")
	}
}

func TestSARIFContainsRule(t *testing.T) {
	r := model.ScanResult{
		Findings: []model.Finding{
			{
				ID:             "gcp.api_key.unrestricted",
				Check:          "API Key Restrictions",
				Severity:       model.SeverityHigh,
				Summary:        "API key has no restrictions",
				Description:    "desc",
				Recommendation: "fix",
				Resource:       "path/to/file.tf",
			},
		},
	}

	b, err := SARIF(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := string(b)
	if !strings.Contains(text, "gcp.api_key.unrestricted") {
		t.Fatalf("sarif did not include rule id")
	}
}
