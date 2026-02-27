package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

func (s *Scanner) scanServiceAccountKeys(ctx context.Context) ([]model.Finding, error) {
	accounts, err := s.gcloudJSON(ctx, "iam", "service-accounts", "list", "--project", s.opts.Project)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()

	for _, account := range accounts {
		email := asString(account["email"])
		if email == "" {
			continue
		}

		keys, keyErr := s.gcloudJSON(
			ctx,
			"iam", "service-accounts", "keys", "list",
			"--iam-account", email,
			"--managed-by", "user",
			"--project", s.opts.Project,
		)
		if keyErr != nil {
			return nil, keyErr
		}

		for _, key := range keys {
			if asBool(key["disabled"]) {
				continue
			}

			keyName := asString(key["name"])
			createdAt := asString(key["validAfterTime"])
			expiresAt := asString(key["validBeforeTime"])

			if expiresAt == "" {
				findings = append(findings, model.Finding{
					ID:       "gcp.sa_key.no_expiry",
					Check:    "Mandatory Rotation",
					Severity: model.SeverityHigh,
					Summary:  "Service account key has no expiration",
					Description: fmt.Sprintf(
						"User-managed key `%s` in `%s` does not show an expiration boundary.",
						keyName,
						email,
					),
					Resource:       keyName,
					Recommendation: "Enforce `constraints/iam.serviceAccountKeyExpiryHours` and rotate this key.",
					Metadata: map[string]string{
						"service_account": email,
						"key_name":        keyName,
					},
				})
			}

			createdTime, parseErr := time.Parse(time.RFC3339, createdAt)
			if parseErr != nil {
				continue
			}

			if int(now.Sub(createdTime).Hours()/24) >= s.opts.InactiveDays {
				findings = append(findings, model.Finding{
					ID:       "gcp.sa_key.stale_review",
					Check:    "Disable Dormant Keys",
					Severity: model.SeverityMedium,
					Summary:  "Old user-managed key should be reviewed",
					Description: fmt.Sprintf(
						"Key `%s` (%s) is older than %d days. Validate recent usage and disable if dormant.",
						keyName,
						email,
						s.opts.InactiveDays,
					),
					Resource:       keyName,
					Recommendation: "Audit usage (logs/metrics), disable dormant keys, and prefer keyless auth (Workload Identity Federation) when possible.",
					Metadata: map[string]string{
						"service_account": email,
						"key_name":        keyName,
						"created_at":      createdAt,
					},
				})
			}
		}
	}

	return findings, nil
}
