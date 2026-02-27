package scanner

import (
	"context"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

func (s *Scanner) scanOrgPolicies(ctx context.Context) ([]model.Finding, error) {
	findings := make([]model.Finding, 0, 2)

	expiryPolicyList, err := s.gcloudJSON(
		ctx,
		"resource-manager", "org-policies", "describe",
		"constraints/iam.serviceAccountKeyExpiryHours",
		"--project", s.opts.Project,
	)
	if err != nil {
		return nil, err
	}
	if len(expiryPolicyList) > 0 && !policyHasRules(expiryPolicyList[0]) {
		findings = append(findings, model.Finding{
			ID:             "gcp.org_policy.key_expiry_missing",
			Check:          "Mandatory Rotation",
			Severity:       model.SeverityHigh,
			Summary:        "Service account key max lifetime policy is not configured",
			Description:    "`constraints/iam.serviceAccountKeyExpiryHours` does not appear to have active rules.",
			Resource:       s.opts.Project,
			Recommendation: "Set an enforced maximum lifetime for user-managed service account keys.",
		})
	}

	disableCreationPolicyList, err := s.gcloudJSON(
		ctx,
		"resource-manager", "org-policies", "describe",
		"constraints/iam.managed.disableServiceAccountKeyCreation",
		"--project", s.opts.Project,
	)
	if err != nil {
		return nil, err
	}
	if len(disableCreationPolicyList) > 0 && !policyEnforcesBoolean(disableCreationPolicyList[0]) {
		findings = append(findings, model.Finding{
			ID:             "gcp.org_policy.disable_key_creation_missing",
			Check:          "Mandatory Rotation",
			Severity:       model.SeverityMedium,
			Summary:        "Service account key creation is not disabled by policy",
			Description:    "`constraints/iam.managed.disableServiceAccountKeyCreation` is not enforced.",
			Resource:       s.opts.Project,
			Recommendation: "If key-based auth is not required, enforce policy to disable new user-managed service account keys.",
		})
	}

	return findings, nil
}

func policyHasRules(policy map[string]any) bool {
	spec := asMap(policy["spec"])
	if len(spec) == 0 {
		return false
	}
	rules := asSlice(spec["rules"])
	return len(rules) > 0
}

func policyEnforcesBoolean(policy map[string]any) bool {
	spec := asMap(policy["spec"])
	rules := asSlice(spec["rules"])
	for _, item := range rules {
		rule := asMap(item)
		if asBool(rule["enforce"]) {
			return true
		}
		if bp := asMap(rule["booleanPolicy"]); asBool(bp["enforced"]) {
			return true
		}
	}
	return false
}
