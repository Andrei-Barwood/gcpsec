package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestScanLocalRepoDetectsAPIKeyPattern(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "main.tf")
	secret := "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := os.WriteFile(file, []byte("api_key=\""+secret+"\""), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	s := New(Options{RepoPath: tmp})
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatalf("expected findings, got none")
	}
}
