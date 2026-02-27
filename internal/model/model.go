package model

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	ID             string            `json:"id"`
	Check          string            `json:"check"`
	Severity       Severity          `json:"severity"`
	Summary        string            `json:"summary"`
	Description    string            `json:"description"`
	Resource       string            `json:"resource,omitempty"`
	Recommendation string            `json:"recommendation"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type ScanResult struct {
	GeneratedAt time.Time `json:"generated_at"`
	Project     string    `json:"project,omitempty"`
	Repo        string    `json:"repo,omitempty"`
	Findings    []Finding `json:"findings"`
	Notes       []string  `json:"notes,omitempty"`
}
