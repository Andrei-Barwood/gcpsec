package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/Andrei-Barwood/gcpsec/internal/execx"
	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

type Options struct {
	Project      string
	RepoPath     string
	InactiveDays int
	Runner       execx.Runner
	Timeout      time.Duration
}

type Scanner struct {
	opts   Options
	runner execx.Runner
}

func New(opts Options) *Scanner {
	if opts.InactiveDays <= 0 {
		opts.InactiveDays = 30
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.Runner == nil {
		opts.Runner = execx.OSRunner{}
	}

	return &Scanner{opts: opts, runner: opts.Runner}
}

func (s *Scanner) Scan(ctx context.Context) (model.ScanResult, error) {
	result := model.ScanResult{
		GeneratedAt: time.Now().UTC(),
		Project:     s.opts.Project,
		Repo:        s.opts.RepoPath,
	}

	localFindings, err := s.scanLocalRepo(ctx)
	if err != nil {
		result.Notes = append(result.Notes, fmt.Sprintf("local repo scan failed: %v", err))
	} else {
		result.Findings = append(result.Findings, localFindings...)
	}

	if s.opts.Project == "" {
		result.Notes = append(result.Notes, "project not set; skipping gcloud-based checks")
		return result, nil
	}

	if _, err := s.runner.LookPath("gcloud"); err != nil {
		result.Notes = append(result.Notes, "gcloud not found in PATH; skipping gcloud-based checks")
		return result, nil
	}

	checks := []struct {
		name string
		run  func(context.Context) ([]model.Finding, error)
	}{
		{name: "api key restrictions", run: s.scanAPIKeys},
		{name: "service account keys", run: s.scanServiceAccountKeys},
		{name: "org policies", run: s.scanOrgPolicies},
		{name: "essential contacts", run: s.scanEssentialContacts},
	}

	for _, check := range checks {
		findings, runErr := check.run(ctx)
		if runErr != nil {
			result.Notes = append(result.Notes, fmt.Sprintf("%s check failed: %v", check.name, runErr))
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}

	return result, nil
}

func (s *Scanner) cmdCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, s.opts.Timeout)
}
