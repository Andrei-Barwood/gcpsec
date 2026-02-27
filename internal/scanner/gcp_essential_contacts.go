package scanner

import (
	"context"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

func (s *Scanner) scanEssentialContacts(ctx context.Context) ([]model.Finding, error) {
	contacts, err := s.gcloudJSON(
		ctx,
		"essential-contacts", "contacts", "list",
		"--project", s.opts.Project,
	)
	if err != nil {
		return nil, err
	}

	if len(contacts) > 0 {
		return nil, nil
	}

	return []model.Finding{
		{
			ID:             "gcp.essential_contacts.none",
			Check:          "Incident Readiness",
			Severity:       model.SeverityMedium,
			Summary:        "No Essential Contacts configured",
			Description:    "This project appears to have no Essential Contacts, which can delay incident response.",
			Resource:       s.opts.Project,
			Recommendation: "Add security and operations contacts in Google Cloud Essential Contacts.",
		},
	}, nil
}
