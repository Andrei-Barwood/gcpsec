package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Andrei-Barwood/gcpsec/internal/execx"
	"github.com/Andrei-Barwood/gcpsec/internal/format"
	"github.com/Andrei-Barwood/gcpsec/internal/model"
	"github.com/Andrei-Barwood/gcpsec/internal/report"
	"github.com/Andrei-Barwood/gcpsec/internal/scanner"
)

const defaultScanPath = ".gcpsec/scan.json"

func Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		printRootUsage(os.Stderr)
		return 2
	}

	cmd := args[0]
	cmdArgs := args[1:]

	var err error
	switch cmd {
	case "scan":
		err = runScan(ctx, cmdArgs)
	case "recommend":
		err = runRecommend(cmdArgs)
	case "report":
		err = runReport(cmdArgs)
	case "enforce":
		err = runEnforce(ctx, cmdArgs)
	case "help", "-h", "--help":
		printRootUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printRootUsage(os.Stderr)
		return 2
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func runScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	project := fs.String("project", "", "Google Cloud project id")
	repoPath := fs.String("repo", ".", "Repository path to inspect")
	inactiveDays := fs.Int("inactive-days", 30, "Days threshold for stale key review")
	outPath := fs.String("out", defaultScanPath, "Path to store raw scan JSON")
	stdoutFormat := fs.String("stdout-format", "summary", "Output format: summary|json|markdown")

	if err := fs.Parse(args); err != nil {
		return err
	}

	s := scanner.New(scanner.Options{
		Project:      strings.TrimSpace(*project),
		RepoPath:     strings.TrimSpace(*repoPath),
		InactiveDays: *inactiveDays,
	})

	result, err := s.Scan(ctx)
	if err != nil {
		return err
	}

	jsonBytes, err := format.JSON(result)
	if err != nil {
		return err
	}

	if *outPath != "" {
		if err := report.Save(*outPath, jsonBytes); err != nil {
			return err
		}
	}

	switch strings.ToLower(strings.TrimSpace(*stdoutFormat)) {
	case "summary":
		printSummary(os.Stdout, result, *outPath)
	case "json":
		_, err = os.Stdout.Write(jsonBytes)
	case "markdown", "md":
		md, mdErr := format.Markdown(result)
		if mdErr != nil {
			return mdErr
		}
		_, err = os.Stdout.Write(md)
	default:
		return fmt.Errorf("invalid stdout-format: %s", *stdoutFormat)
	}
	return err
}

func runRecommend(args []string) error {
	fs := flag.NewFlagSet("recommend", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	from := fs.String("from", defaultScanPath, "Input scan JSON file")
	out := fs.String("out", "", "Optional output path")
	outputFormat := fs.String("format", "table", "Output format: table|json")

	if err := fs.Parse(args); err != nil {
		return err
	}

	scan, err := report.LoadScan(*from)
	if err != nil {
		return err
	}

	recs := report.BuildRecommendations(scan.Findings)
	var payload []byte
	switch strings.ToLower(strings.TrimSpace(*outputFormat)) {
	case "table":
		payload = []byte(renderRecommendationsTable(recs))
	case "json":
		payload, err = json.MarshalIndent(recs, "", "  ")
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid format: %s", *outputFormat)
	}

	if *out != "" {
		if err := report.Save(*out, payload); err != nil {
			return err
		}
	}

	_, err = os.Stdout.Write(payload)
	return err
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	from := fs.String("from", defaultScanPath, "Input scan JSON file")
	out := fs.String("out", "", "Optional output path")
	outputFormat := fs.String("format", "markdown", "Output format: json|markdown|sarif")

	if err := fs.Parse(args); err != nil {
		return err
	}

	scan, err := report.LoadScan(*from)
	if err != nil {
		return err
	}

	var payload []byte
	switch strings.ToLower(strings.TrimSpace(*outputFormat)) {
	case "json":
		payload, err = format.JSON(scan)
	case "markdown", "md":
		payload, err = format.Markdown(scan)
	case "sarif":
		payload, err = format.SARIF(scan)
	default:
		return fmt.Errorf("invalid format: %s", *outputFormat)
	}
	if err != nil {
		return err
	}

	if *out != "" {
		if err := report.Save(*out, payload); err != nil {
			return err
		}
	}

	_, err = os.Stdout.Write(payload)
	return err
}

func runEnforce(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enforce", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	from := fs.String("from", defaultScanPath, "Input scan JSON file")
	project := fs.String("project", "", "Google Cloud project id (overrides scan file value)")
	apply := fs.Bool("apply", false, "Execute remediations (default dry-run)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	scan, err := report.LoadScan(*from)
	if err != nil {
		return err
	}

	resolvedProject := strings.TrimSpace(*project)
	if resolvedProject == "" {
		resolvedProject = scan.Project
	}
	if resolvedProject == "" {
		return errors.New("project is required for enforce; pass --project or include it in the scan file")
	}

	actions := buildEnforceActions(scan, resolvedProject)
	if len(actions) == 0 {
		fmt.Fprintln(os.Stdout, "No auto-remediations available for current findings.")
		return nil
	}

	if !*apply {
		fmt.Fprintln(os.Stdout, "Dry run: planned actions")
		for _, act := range actions {
			fmt.Fprintf(os.Stdout, "- [%s] %s\n", act.Kind, strings.Join(act.Cmd, " "))
		}
		fmt.Fprintln(os.Stdout, "\nRe-run with --apply to execute supported actions.")
		return nil
	}

	runner := execx.OSRunner{}
	success := 0
	for _, act := range actions {
		out, runErr := runner.Run(ctx, act.Cmd[0], act.Cmd[1:]...)
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "failed [%s]: %v\n", act.Kind, runErr)
			continue
		}
		success++
		if len(strings.TrimSpace(string(out))) > 0 {
			fmt.Fprintln(os.Stdout, strings.TrimSpace(string(out)))
		}
	}

	fmt.Fprintf(os.Stdout, "Applied %d/%d actions.\n", success, len(actions))
	return nil
}

type enforceAction struct {
	Kind string
	Cmd  []string
}

func buildEnforceActions(scan model.ScanResult, project string) []enforceAction {
	actions := make([]enforceAction, 0)
	seen := map[string]struct{}{}

	for _, f := range scan.Findings {
		if f.ID != "gcp.sa_key.stale_review" {
			continue
		}

		account := f.Metadata["service_account"]
		keyName := f.Metadata["key_name"]
		if account == "" || keyName == "" {
			continue
		}

		keyID := keyName
		if strings.Contains(keyName, "/") {
			parts := strings.Split(strings.TrimSpace(keyName), "/")
			keyID = parts[len(parts)-1]
		}
		if keyID == "" {
			continue
		}

		cmd := []string{
			"gcloud", "iam", "service-accounts", "keys", "disable", keyID,
			"--iam-account", account,
			"--project", project,
		}
		sig := strings.Join(cmd, " ")
		if _, exists := seen[sig]; exists {
			continue
		}
		seen[sig] = struct{}{}
		actions = append(actions, enforceAction{
			Kind: "disable_stale_key",
			Cmd:  cmd,
		})
	}

	sort.SliceStable(actions, func(i, j int) bool {
		return strings.Join(actions[i].Cmd, " ") < strings.Join(actions[j].Cmd, " ")
	})

	return actions
}

func renderRecommendationsTable(recs []report.Recommendation) string {
	if len(recs) == 0 {
		return "No recommendations.\n"
	}

	var b strings.Builder
	b.WriteString("PRIORITY  CHECK                     FINDINGS  ACTION\n")
	b.WriteString("--------  ------------------------  --------  ------\n")
	for _, r := range recs {
		fmt.Fprintf(
			&b,
			"%-8s  %-24s  %-8d  %s\n",
			r.Priority,
			truncate(r.Title, 24),
			r.Count,
			r.Action,
		)
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func printRootUsage(w *os.File) {
	fmt.Fprintln(w, "gcpsec - Google Cloud credential security CLI")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  gcpsec <command> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  scan       Run security checks and generate scan JSON")
	fmt.Fprintln(w, "  recommend  Convert findings into prioritized actions")
	fmt.Fprintln(w, "  enforce    Apply safe remediations (dry-run by default)")
	fmt.Fprintln(w, "  report     Render scan output as markdown/json/sarif")
}

func printSummary(w *os.File, result model.ScanResult, outPath string) {
	counts := map[model.Severity]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	fmt.Fprintln(w, "gcpsec scan summary")
	fmt.Fprintf(w, "- findings: %d\n", len(result.Findings))
	fmt.Fprintf(w, "- critical: %d\n", counts[model.SeverityCritical])
	fmt.Fprintf(w, "- high: %d\n", counts[model.SeverityHigh])
	fmt.Fprintf(w, "- medium: %d\n", counts[model.SeverityMedium])
	fmt.Fprintf(w, "- low: %d\n", counts[model.SeverityLow])
	fmt.Fprintf(w, "- info: %d\n", counts[model.SeverityInfo])
	if outPath != "" {
		fmt.Fprintf(w, "- saved: %s\n", outPath)
	}
	if len(result.Notes) > 0 {
		fmt.Fprintln(w, "- notes:")
		for _, note := range result.Notes {
			fmt.Fprintf(w, "  - %s\n", note)
		}
	}
}
