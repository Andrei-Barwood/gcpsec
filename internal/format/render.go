package format

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

func JSON(result model.ScanResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

func Markdown(result model.ScanResult) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# gcpsec report\n\n")
	fmt.Fprintf(&b, "- Generated: `%s`\n", result.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	if result.Project != "" {
		fmt.Fprintf(&b, "- Project: `%s`\n", result.Project)
	}
	if result.Repo != "" {
		fmt.Fprintf(&b, "- Repo: `%s`\n", result.Repo)
	}
	fmt.Fprintf(&b, "- Findings: `%d`\n\n", len(result.Findings))

	if len(result.Findings) == 0 {
		b.WriteString("No findings.\n")
	} else {
		sorted := append([]model.Finding(nil), result.Findings...)
		sort.SliceStable(sorted, func(i, j int) bool {
			return severityWeight(sorted[i].Severity) > severityWeight(sorted[j].Severity)
		})

		for _, f := range sorted {
			fmt.Fprintf(&b, "## [%s] %s\n\n", strings.ToUpper(string(f.Severity)), f.Summary)
			fmt.Fprintf(&b, "- Check: `%s`\n", f.Check)
			if f.Resource != "" {
				fmt.Fprintf(&b, "- Resource: `%s`\n", f.Resource)
			}
			fmt.Fprintf(&b, "- Description: %s\n", f.Description)
			fmt.Fprintf(&b, "- Recommendation: %s\n\n", f.Recommendation)
		}
	}

	if len(result.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, note := range result.Notes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		b.WriteString("\n")
	}

	return []byte(b.String()), nil
}

func SARIF(result model.ScanResult) ([]byte, error) {
	type rule struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		ShortDescription struct {
			Text string `json:"text"`
		} `json:"shortDescription"`
	}
	type artifactLocation struct {
		URI string `json:"uri"`
	}
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation artifactLocation `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type resultItem struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   any        `json:"message"`
		Locations []location `json:"locations,omitempty"`
	}

	rulesByID := make(map[string]rule)
	results := make([]resultItem, 0, len(result.Findings))

	for _, f := range result.Findings {
		if _, ok := rulesByID[f.ID]; !ok {
			r := rule{ID: f.ID, Name: f.Check}
			r.ShortDescription.Text = f.Summary
			rulesByID[f.ID] = r
		}

		item := resultItem{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: map[string]string{"text": fmt.Sprintf("%s Recommendation: %s", f.Description, f.Recommendation)},
		}
		if f.Resource != "" && !strings.Contains(f.Resource, "@") {
			item.Locations = []location{{}}
			item.Locations[0].PhysicalLocation.ArtifactLocation.URI = filepath.ToSlash(f.Resource)
		}
		results = append(results, item)
	}

	rules := make([]rule, 0, len(rulesByID))
	for _, r := range rulesByID {
		rules = append(rules, r)
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	payload := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":            "gcpsec",
						"informationUri":  "https://github.com/Andrei-Barwood/gcpsec",
						"semanticVersion": "0.1.0",
						"rules":           rules,
					},
				},
				"results": results,
			},
		},
	}

	return json.MarshalIndent(payload, "", "  ")
}

func severityWeight(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	default:
		return 1
	}
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium, model.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}
