package scanner

import (
	"context"
	"fmt"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

func (s *Scanner) scanAPIKeys(ctx context.Context) ([]model.Finding, error) {
	keys, err := s.gcloudJSON(ctx, "services", "api-keys", "list", "--project", s.opts.Project)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	for _, key := range keys {
		name := asString(key["name"])
		displayName := asString(key["displayName"])
		resource := displayName
		if resource == "" {
			resource = name
		}

		restrictions := asMap(key["restrictions"])
		if len(restrictions) == 0 {
			findings = append(findings, model.Finding{
				ID:       "gcp.api_key.unrestricted",
				Check:    "API Key Restrictions",
				Severity: model.SeverityHigh,
				Summary:  "API key has no restrictions",
				Description: fmt.Sprintf(
					"API key `%s` does not define API or environment restrictions.",
					resource,
				),
				Resource:       resource,
				Recommendation: "Restrict this key to specific APIs and add environment restrictions (IP, referrer, Android/iOS app, etc.).",
			})
			continue
		}

		hasAPITargets := len(asSlice(restrictions["apiTargets"])) > 0
		hasEnvRestrictions := len(asMap(restrictions["browserKeyRestrictions"])) > 0 ||
			len(asMap(restrictions["serverKeyRestrictions"])) > 0 ||
			len(asMap(restrictions["androidKeyRestrictions"])) > 0 ||
			len(asMap(restrictions["iosKeyRestrictions"])) > 0

		if !hasAPITargets {
			findings = append(findings, model.Finding{
				ID:       "gcp.api_key.missing_api_targets",
				Check:    "API Key Restrictions",
				Severity: model.SeverityMedium,
				Summary:  "API key is missing API-level restrictions",
				Description: fmt.Sprintf(
					"API key `%s` has environment restrictions but no API targets.",
					resource,
				),
				Resource:       resource,
				Recommendation: "Limit the key to only required APIs (for example, Maps JavaScript API only).",
			})
		}

		if !hasEnvRestrictions {
			findings = append(findings, model.Finding{
				ID:       "gcp.api_key.missing_environment_restrictions",
				Check:    "API Key Restrictions",
				Severity: model.SeverityMedium,
				Summary:  "API key is missing environment restrictions",
				Description: fmt.Sprintf(
					"API key `%s` is API-restricted but not bound to an environment.",
					resource,
				),
				Resource:       resource,
				Recommendation: "Add referrer/IP/mobile app restrictions so the key cannot be reused from unauthorized environments.",
			})
		}
	}

	return findings, nil
}
