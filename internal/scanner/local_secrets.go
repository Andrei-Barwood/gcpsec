package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

var (
	apiKeyRegex          = regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)
	serviceAccountTypeRx = regexp.MustCompile(`"type"\s*:\s*"service_account"`)
)

const maxReadBytes = 512 * 1024

func (s *Scanner) scanLocalRepo(_ context.Context) ([]model.Finding, error) {
	if s.opts.RepoPath == "" {
		return nil, nil
	}

	root, err := filepath.Abs(s.opts.RepoPath)
	if err != nil {
		return nil, err
	}

	var findings []model.Finding
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		name := d.Name()
		if d.IsDir() {
			if shouldSkipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkipFile(name) {
			return nil
		}

		matches, err := scanFileForSecrets(path)
		if err != nil {
			return nil
		}

		for _, m := range matches {
			findings = append(findings, model.Finding{
				ID:       "local.secret.exposure",
				Check:    "Zero-Code Storage",
				Severity: model.SeverityHigh,
				Summary:  "Possible credential detected in repository",
				Description: fmt.Sprintf(
					"Potential secret pattern `%s` found in `%s`.",
					m,
					trimRepoRoot(root, path),
				),
				Resource:       trimRepoRoot(root, path),
				Recommendation: "Move the credential to Secret Manager, remove it from git history, and rotate it immediately.",
			})
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return dedupeLocalFindings(findings), nil
}

func scanFileForSecrets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	limited := io.LimitReader(f, maxReadBytes)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	if !isLikelyText(buf) {
		return nil, nil
	}

	var matches []string
	if apiKeyRegex.Match(buf) {
		matches = append(matches, "Google API Key")
	}
	if bytes.Contains(buf, []byte("-----BEGIN PRIVATE KEY-----")) {
		matches = append(matches, "Private Key Block")
	}
	if serviceAccountTypeRx.Match(buf) {
		scanner := bufio.NewScanner(bytes.NewReader(buf))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "client_email") || strings.Contains(line, "private_key") {
				matches = append(matches, "Service Account JSON")
				break
			}
		}
	}

	return matches, nil
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "dist", "build", ".idea", ".vscode":
		return true
	default:
		return false
	}
}

func shouldSkipFile(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".ico", ".mov", ".mp4", ".mp3", ".class", ".jar"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func isLikelyText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if bytes.IndexByte(b, 0x00) >= 0 {
		return false
	}
	return utf8.Valid(b)
}

func trimRepoRoot(root, full string) string {
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return full
	}
	return rel
}

func dedupeLocalFindings(findings []model.Finding) []model.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		k := f.Resource + "|" + f.Description
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}
	return out
}
