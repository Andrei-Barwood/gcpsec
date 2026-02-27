package report

import (
	"sort"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

type Recommendation struct {
	Priority string `json:"priority"`
	Title    string `json:"title"`
	Action   string `json:"action"`
	Count    int    `json:"count"`
}

func BuildRecommendations(findings []model.Finding) []Recommendation {
	type bucket struct {
		maxSeverity model.Severity
		check       string
		action      string
		count       int
	}

	buckets := map[string]*bucket{}
	for _, f := range findings {
		key := f.Check + "|" + f.Recommendation
		entry, ok := buckets[key]
		if !ok {
			entry = &bucket{
				maxSeverity: f.Severity,
				check:       f.Check,
				action:      f.Recommendation,
			}
			buckets[key] = entry
		}
		if severityRank(f.Severity) > severityRank(entry.maxSeverity) {
			entry.maxSeverity = f.Severity
		}
		entry.count++
	}

	out := make([]Recommendation, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, Recommendation{
			Priority: priorityFromSeverity(b.maxSeverity),
			Title:    b.check,
			Action:   b.action,
			Count:    b.count,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		ri := priorityRank(out[i].Priority)
		rj := priorityRank(out[j].Priority)
		if ri == rj {
			return out[i].Count > out[j].Count
		}
		return ri > rj
	})

	return out
}

func severityRank(s model.Severity) int {
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

func priorityFromSeverity(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "P1"
	case model.SeverityMedium:
		return "P2"
	case model.SeverityLow:
		return "P3"
	default:
		return "P4"
	}
}

func priorityRank(p string) int {
	switch p {
	case "P1":
		return 4
	case "P2":
		return 3
	case "P3":
		return 2
	default:
		return 1
	}
}
