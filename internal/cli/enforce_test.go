package cli

import (
	"testing"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

func TestBuildEnforceActionsForStaleKeys(t *testing.T) {
	scan := model.ScanResult{
		Project: "demo-project",
		Findings: []model.Finding{
			{
				ID: "gcp.sa_key.stale_review",
				Metadata: map[string]string{
					"service_account": "svc@demo-project.iam.gserviceaccount.com",
					"key_name":        "projects/demo-project/serviceAccounts/svc@demo-project.iam.gserviceaccount.com/keys/1234567890abcdef",
				},
			},
		},
	}

	actions := buildEnforceActions(scan, scan.Project)
	if len(actions) != 1 {
		t.Fatalf("expected one action, got %d", len(actions))
	}

	got := actions[0].Cmd
	wantLast := "1234567890abcdef"
	if got[5] != wantLast {
		t.Fatalf("expected key id %s, got %s", wantLast, got[5])
	}
}
